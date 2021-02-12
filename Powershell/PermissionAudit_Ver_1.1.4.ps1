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
    Author: Mariusz Rus
    Last Edit: 2021-02-10
    Version 1.0 - initial release of PermissionAudit
    Version 1.1.2 - Added Menus and Option to include deleted objects
    Version 1.1.3 - Added Added more info messages and progress. Added ability to run from command line with no menus. 
    Version 1.1.4 - Various small code prettifiers. Upload to GitHub
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
        $ObjectsInContext = get-adobject -Filter *  -SearchScope Subtree -IncludeDeletedObjects -SearchBase $PartionToAttach -Properties DistinguishedName, nTSecurityDescriptor
        }
    'n' {
        Clear-Host
        write-host "Retriving list of objects from $PartionToAttach "
        $ObjectsInContext = get-adobject -Filter *  -SearchScope Subtree  -SearchBase $PartionToAttach -Properties DistinguishedName, nTSecurityDescriptor
        }
    'c' {
        Write-Host "Ok Canceling "
        Exit #Exit script
        }
}


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
        #$y++
        #endofaccessloop
    }

    $PermissionsColected |  Export-Csv -Path $SaveToFile -Force -NoTypeInformation -Append -Encoding UTF8
  
    
    $z++
    #endoflookforqueryineachcontext
}

$NameOfscript = $MyInvocation.MyCommand.Name
$Mydate = Get-Date -Format "yyyy-MM-dd-HH-mm"
$SaveToFile = ".\Permissions_$AddNameCTX" + "_" + $Mydate.ToString() + ".csv"
$nextTimeCommand = ".\$NameOfscript -namingcontext " + '"' + "$PartionToAttach" + '"' +  " -includedeletedobjects " + '"' +  "$includedeletedobjects"  + '"'  + " -outputfile " + '"' + "$SaveToFile" + '"'

Write-host "Next time you can run following command to skip menu `n" -ForegroundColor Green
Write-Host $nextTimeCommand  -ForegroundColor Green
Write-Host "`n"

