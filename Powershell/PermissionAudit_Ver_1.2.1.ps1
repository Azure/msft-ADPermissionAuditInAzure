param(
[string]$namingcontext,
[string]$includedeletedobjects,
[string]$outputfile
)

<#
.SYNOPSIS
    This script/function Collects non-inherited permissions from all AD objects in selected name space. 

.DESCRIPTION
    This script/function Collects non-inherited permissions from all AD objects in selected name space. It has option to include deleted objects from that name space

.PARAMETER namingcontext
    The parameter namingcontext is used to define the naming context to search
    Example. would be "DC=contoso,DC=com" or you could use OU path like this "OU=accounts,DC=contoso,DC=com"

.PARAMETER includedeletedobjects
    The parameter includedeletedobjects is used to define if Deleted objects should be searched or not.
    Options are "y", "n", "c" for cancel script.

 .PARAMETER $outputfile
    The parameter $outputfile is used to define path where CSV file is saved. This is optional as if ommitted script will save file to the location of your powershell location session
    example would be "c:\temp\mylog.csv"
.EXAMPLE
    The example below does blah
    PS C:\> .\get-AccessADRight.ps1 -namingcontext "DC=contoso,DC=com" -includedeletedobjects "y" 

.EXAMPLE
    Another example : if you run script with no paramaters, menu will appear allowing selection of context and if deleted objects should be included.
    PS C:\> .\get-AccessADRight.ps1

.NOTES
    Author: Mariusz Rus, Jason Rahn
    Last Edit: 2021-02-10
    Version 1.0 - initial release of PermissionAudit
    Version 1.1.2 - Added Menus and Option to include deleted objects
    Version 1.1.3 - Added Added more info messages and progress. Added ability to run from command line with no menus. 
    Version 1.1.4 - Various small code prettifiers. Upload to GitHub 
    :TODO add inheritance option
    :TODO add Agent file as seprate from csv
#>




Function Start-MenuNamingContext {
    param(
    [string]$namingcontextinfunction
    )
    $ReadRootDSEObject = Get-adrootdse
    $retriveNamingContext = $ReadRootDSEObject | Select-Object -ExpandProperty namingContexts
    #$PermissionsColected = @()
    $ItemCount = $retriveNamingContext.Count
    [int]$iindex = 0

    Write-Host " Select Naming context to process by typing ID number and pressing enter `n" -BackgroundColor White -ForegroundColor DarkBlue
    Write-Host
    Foreach ($Context in $retriveNamingContext) {

        [string]$stringMenu = "$iindex" + " ------- " + $retriveNamingContext[$iindex]
        Write-Host $stringMenu -ForegroundColor Green
        $iindex++
    }

    If ($namingcontextinfunction -like "default"){
    $inputID = 0
    Return $retriveNamingContext[$inputID]


    }
    ElseIf ($namingcontextinfunction -like ""){
    $inputID = Read-Host -Prompt "Type ID of the naming context "

            If ($inputID -lt $ItemCount) {
        Return $retriveNamingContext[$inputID]
    }
            Else {
        $inputID = "-1"
        Return $input
    }

    }
    Else{
     Return $namingcontextinfunction
    }
    

    


    #ENDOFFUNCTION Start-MenuNamingContext
}

Function Start-MenuIncludeDeleted {
    $answer = Read-Host "Do you want to include deleted objects in the search ? y or n or c for Cancel" 

    while ("y", "n", "c" -notcontains $answer) {
        $answer = Read-Host "Do you want to include deleted objects in the search ? y or n or c for Cancel"
    }

    Return $answer

}

function Get-accessmaskstring{
    param(
            [int32]$accessmasknum

    )
    $strOfAcessMask = ""
    $arrayOfValues = @()
 
[Flags()] enum ActiveDirectoryRightsEnum {
    AccessSystemSecurity = 16777216
    CreateChild = 1
    Delete = 65536
    DeleteChild = 2
    DeleteTree = 64
    ExtendedRight = 256
    GenericAll = 983551
    GenericExecute = 131076
    GenericRead = 131220
    GenericWrite = 131112
    ListChildren = 4
    ListObject = 128
    ReadControl = 131072
    ReadProperty = 16
    Self = 8
    Synchronize = 1048576
    WriteDacl = 262144
    WriteOwner = 524288
    WriteProperty = 32
}

If ($accessmasknum -like '-1'){
[string]$listofacces = '-1'

}
else{
[ActiveDirectoryRightsEnum]$strOfAcessMask = [ActiveDirectoryRightsEnum]$accessmasknum 

[string]$listofacces = $strOfAcessMask.ToString()
$arrayOfValues = ($listofacces -split "," -replace " ","")

}


RETURN $listofacces
#https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-5.0

#endoffunction Get-accessmaskstring
}

Function queryobjectsfromAD{
param(
            [string]$ldappath,

            [string]$logfilepath,

            [boolean]$Tombstone

    )

$adsisearcher = New-Object system.directoryservices.directorysearcher 
$adsisearcher.PropertiesToLoad.Add("DistinguishedName")
$adsisearcher.PropertiesToLoad.Add("nTSecurityDescriptor")
$adsisearcher.SearchRoot = $ldappath 
#$adsisearcher.SizeLimit = 2147483647
$adsisearcher.SizeLimit = 1000
$adsisearcher.PageSize = 4000
$adsisearcher.Tombstone = $Tombstone
$data = $adsisearcher.FindAll()
$y=1
$numberofobjectstoprocess = $data.Count

Foreach ($Dentry in $data){
    $Props = $Dentry.Properties
    $test = ''
$Mychararray = $props.ntsecuritydescriptor
$SecDesctest=$Mychararray.Item(0)
$DNofObject = $props.distinguishedname
$helloMydarling = [System.Security.AccessControl.RawSecurityDescriptor]::new($SecDesctest,0)
$allACLEntry = $helloMydarling.DiscretionaryAcl
Write-Progress -Id 0 -Activity "Processing objects" -Status "Progress:" -PercentComplete ($y/$numberofobjectstoprocess*100)

foreach ($ACLentry in $allACLEntry){
$Emptyarray = @()


$MyValueofaccessmask = Get-accessmaskstring  ($ACLentry).AccessMask
 If (($ACLentry).IsInherited -like "false"){
 
                    $obj = New-Object PSObject  
                    $obj |Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $DNofObject[0]
                    $obj |Add-Member -MemberType NoteProperty -Name "ActiveDirectoryRights" -Value $MyValueofaccessmask
                    $obj |Add-Member -MemberType NoteProperty -Name "AceType" -Value $ACLentry.AceType
                    $obj |Add-Member -MemberType NoteProperty -Name "SecurityIdentifier" -Value $ACLentry.SecurityIdentifier
                    $obj |Add-Member -MemberType NoteProperty -Name "BinaryLength" -Value $ACLentry.BinaryLength
                    $obj |Add-Member -MemberType NoteProperty -Name "AceQualifier" -Value $ACLentry.AceQualifier
                    $obj |Add-Member -MemberType NoteProperty -Name "IsCallback" -Value $ACLentry.IsCallback 
                    $obj |Add-Member -MemberType NoteProperty -Name "OpaqueLength" -Value $ACLentry.OpaqueLength
                    $obj |Add-Member -MemberType NoteProperty -Name "AceFlags" -Value $ACLentry.AceFlags
                    $obj |Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $ACLentry.IsInherited
                    $obj |Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $ACLentry.InheritanceFlags
                    $obj |Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value $ACLentry.PropagationFlags
                    $obj |Add-Member -MemberType NoteProperty -Name "AuditFlags" -Value $ACLentry.AuditFlags
                    $obj |Add-Member -MemberType NoteProperty -Name "ObjectAceType" -Value $ACLentry.ObjectAceType
                    $obj |Add-Member -MemberType NoteProperty -Name "ObjectAceFlags" -Value $ACLentry.ObjectAceFlags

                    $Emptyarray += $obj

 }                   
                   


$Emptyarray | export-csv $logfilepath  -Force -NoTypeInformation -Append
}


$y++
}



#endof queryobjectsfromAD
}

Function processgetadobject {
    param(
    $Listofobjects
    )

#endof processgetadobject
}

#Start of MAIN process
#region begin Mainvariables



$Nameselection = Start-MenuNamingContext -namingcontextinfunction $namingcontext


$builtins = @('NT AUTHORITY', 'BUILTIN') #this filter removes builtin and NT Authority permissions which are OS rights)
$Mydate =""
$Mydate = Get-Date -Format "yyyy-MM-dd-HH-mm"
[string]$PartionToAttach = ""
$ObjectsInContext =''

$z = 1
#endregion

If ( $Nameselection -like "-1") {

    Write-Host "You have selected nonexisting menu item" -ForegroundColor Red
    Exit #Exit script
}
Else {
    $PartionToAttach = $Nameselection
    Write-Host "You have selected $Nameselection" -ForegroundColor Green
}


If ($outputfile -like ""){
    $get_part = ($PartionToAttach -split ",")[0]
    $AddNameCTX = $get_part -replace "DC=", "" -replace "CN=", "" -replace "OU=", ""
    $SaveToFile = ""
    $SaveToFile = ".\Permissions_$AddNameCTX" + "_" + $Mydate.ToString() + ".csv"
}
Else {
    $SaveToFile = ""
    $SaveToFile = $outputfile
}


If ($includedeletedobjects -like ""){
$includedeletedobjects = Start-MenuIncludeDeleted
}
Else {

}




switch ($includedeletedobjects) {
    'y' {
        Clear-Host
        write-host "Retriving list of objects from $PartionToAttach "
        <#
        $ObjectsInContext = get-adobject -Filter *  -SearchScope Subtree -IncludeDeletedObjects -SearchBase $PartionToAttach -Properties DistinguishedName, nTSecurityDescriptor

        $numberofobjectstoprocess = $ObjectsInContext.Count

        foreach ($Object in $ObjectsInContext) {
            Write-Progress -Id 0 -Activity "Processing objects" -Status "Progress:" -PercentComplete ($z/$numberofobjectstoprocess*100)
            $PermissionsColected = @()          #created Empty variable to collect permissions for specific object
            $currentObjectName = $Object.Name
            Write-Host $currentObjectName
            $ListOfAccess = $Object.nTSecurityDescriptor.Access
   
            foreach ($accces in $ListOfAccess) {
              
                $ISinherited = $accces.IsInherited

                If ($ISinherited) {

                    }
                Else {
                    $s = $accces.IdentityReference
                        If ($null -ne ($builtins | Where-Object { $s -match $_ })){


                            }
                             Else {

                                    $obj = New-Object PSObject  
                                    $obj | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $Object.DistinguishedName
                                    $obj | Add-Member -MemberType NoteProperty -Name "ActiveDirectoryRights" -Value $accces.ActiveDirectoryRights
                                    $obj | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $accces.AccessControlType
                                    $obj | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $accces.IdentityReference
                                    $PermissionsColected += $obj
                    
                                }

                }
        
            #endofaccessloop
            }

            $PermissionsColected |  Export-Csv -Path $SaveToFile -Force -NoTypeInformation -Append -Encoding UTF8
  
    
            $z++
    #endoflookforqueryineachcontext
    }
        #>

        #region begin newcode
        $LdapPatition = "LDAP://" + $PartionToAttach

        queryobjectsfromAD -ldappath $LdapPatition -logfilepath $SaveToFile -Tombstone $true

        #endregion

        }
    'n' {
        Clear-Host
        write-host "Retriving list of objects from $PartionToAttach "
        #$ObjectsInContext = get-adobject -Filter *  -SearchScope Subtree  -SearchBase $PartionToAttach -Properties DistinguishedName, nTSecurityDescriptor

        $LdapPatition = "LDAP://" + $PartionToAttach

        queryobjectsfromAD -ldappath $LdapPatition -logfilepath $SaveToFile -Tombstone $false


        }
    'c' {
        Write-Host "Ok Canceling "
        Exit #Exit script
        }
}



$NameOfscript = $MyInvocation.MyCommand.Name
$Mydate = Get-Date -Format "yyyy-MM-dd-HH-mm"
$SaveToFile = ".\Permissions_$AddNameCTX" + "_" + $Mydate.ToString() + ".csv"
$nextTimeCommand = ".\$NameOfscript -namingcontext " + '"' + "$PartionToAttach" + '"' +  " -includedeletedobjects " + '"' +  "$includedeletedobjects"  + '"'  + " -outputfile " + '"' + "$SaveToFile" + '"'

Write-host "Next time you can run following command to skip menu `n" -ForegroundColor Green
Write-Host $nextTimeCommand  -ForegroundColor Green
Write-Host "`n"

