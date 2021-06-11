#requires -Version 7.0
using namespace System.Security.AccessControl

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
    Version 1.2.2 - Added multithreading and ACE type search
    
#>




Function Start-MenuNamingContext {
    param(
    [string]$namingcontextinfunction
    )
    $ReadRootDSEObject = Get-adrootdse
    $retriveNamingContext = $ReadRootDSEObject | Select-Object -ExpandProperty namingContexts
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

Function Get-myExtendedRights{
    $RootConfiguration = Get-ADRootDSE
    #Load SchemaIDs
    $SchemaPath = "CN=Schema," +  $RootConfiguration.configurationNamingContext.ToString()
    $LoadGuids = get-adobject -SearchBase $SchemaPath -SearchScope Subtree -Filter * -Properties SchemaIDGuid
    #Load ExtendedRights
    $extendedRightsPath = "CN=Extended-Rights," +  $RootConfiguration.configurationNamingContext.ToString()
    $extendedRights = get-adobject -SearchBase $extendedRightsPath -SearchScope Subtree -Filter 'ObjectClass -eq "controlAccessRight"' -Properties 'rightsGuid'
    
    $listOfACEguids =@()
    Foreach ($myguid in $LoadGuids){
           
        If ($NULL -ne $myguid.SchemaIDGuid){
            [guid]$ArrayOfGuid = $myguid.SchemaIDGuid
            $GuidtoPSObject = $ArrayOfGuid.ToString()
            $TempPsoobj = [PSObject]::New()
            $TempPsoobj |Add-Member -MemberType NoteProperty -Name "PropName" -Value $myguid.Name
            $TempPsoobj |Add-Member -MemberType NoteProperty -Name "ACETypeGuid" -Value $GuidtoPSObject
            $listOfACEguids += $TempPsoobj
        }
    }

    Foreach ($SingleextendedRight in $extendedRights) {
         If ($NULL -ne $SingleextendedRight.rightsGuid){

                $TempPsoobj = [PSObject]::New()
                $TempPsoobj |Add-Member -MemberType NoteProperty -Name "PropName" -Value $SingleextendedRight.Name
                $TempPsoobj |Add-Member -MemberType NoteProperty -Name "ACETypeGuid" -Value $SingleextendedRight.rightsGuid
                $listOfACEguids += $TempPsoobj

        }
    }

     Return   $listOfACEguids

}


Function Start-MenuIncludeDeleted {
    $answer = Read-Host "Do you want to include deleted objects in the search ? y or n or c for Cancel" 

    while ("y", "n", "c" -notcontains $answer) {
        $answer = Read-Host "Do you want to include deleted objects in the search ? y or n or c for Cancel"
    }

    Return $answer

}

function Global:Get-accessmaskstring{
    param(
            [int32]$accessmasknum

    )
    $strOfAcessMask = ""
    
 
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


}


RETURN $listofacces
#https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-5.0

#endoffunction Get-accessmaskstring
} #endof Get-accessmaskstring function




Function queryobjectsfromADmulti{
    
    param(
                [string]$ldappath,
    
                [string]$logfilepath,
    
                [boolean]$Tombstone
    
        )
    $startRecordpull=Get-date
    
    $adsisearcher = New-Object system.directoryservices.directorysearcher 
    $adsisearcher.PropertiesToLoad.Add("DistinguishedName")
    $adsisearcher.PropertiesToLoad.Add("nTSecurityDescriptor")
    $adsisearcher.SearchRoot = $ldappath 
    $adsisearcher.SizeLimit = 2147483647
    #$adsisearcher.SizeLimit = 1000
    $adsisearcher.PageSize = 4000
    $adsisearcher.Tombstone = $Tombstone
    If ($Tombstone){
        $adsisearcher.Filter = "((isDeleted=TRUE))" #
    }
    $data = $adsisearcher.FindAll()
    [int]$numberofobjectstoprocess = 0
    $numberofobjectstoprocess = $data.Count
    $numberofobjectstoprocess
    $finishedrecordpull = Get-Date
    $totaltimeforrecordpull = $finishedrecordpull - $startRecordpull
    [int]$TrottleProcCount = $ENV:NUMBER_OF_PROCESSORS
    Write-host "$numberofobjectstoprocess Records pulled in $totaltimeforrecordpull" -ForegroundColor Blue
        [int]$arraycount = $data.count

        [int]$startofarray = 0

        [int]$endofarray  =  $startofarray + 10000

        [array]$arrayOfArrays = @()
        #Region Split Data into Array of Arrays
        Do {
            
            $arrayOfArrays += ,$data[$startofarray..$endofarray]
             $startofarray = $endofarray + 1
             $endofarray  =  $startofarray + 9999
         
         } while ($startofarray -le $arraycount)
         #endregion Split Data into Array of Arrays

         #Region Main Loop processing data
         $arrayOfArrays | foreach-object  -Parallel {
         
         [array]$itemarray = $_
         
         
         
         $itemarray | ForEach-Object  {
            function Global:Get-accessmaskstring{
                param(
                        [int32]$accessmasknum
            
                )
                $strOfAcessMask = ""
                
             
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
            
            
            }
            
            
            RETURN $listofacces
            #https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-5.0
            
            #endoffunction Get-accessmaskstring
            } #endof Get-accessmaskstring function
    
            #endofnestedfunction
            $Dentry = $_
            $Props = $Dentry.Properties
            
            $Mychararray = $props.ntsecuritydescriptor
        
            $SecDesctest=$Mychararray.Item(0) 
            $DNofObject = $props.distinguishedname
            $helloMydarling = [System.Security.AccessControl.RawSecurityDescriptor]::new($SecDesctest,0)
            $allACLEntry = $helloMydarling.DiscretionaryAcl
            $ownerValue = $helloMydarling.Owner.Value
            $Emptyarray = @() 
            #comment below
            $a = get-date
            
            foreach ($ACLentry in $allACLEntry) {
            $MyValueofaccessmask = Get-accessmaskstring  ($ACLentry).AccessMask 
             If (($ACLentry).IsInherited -like "false"){
             
                                $obj = [PSObject]::New()
                                $obj |Add-Member -MemberType NoteProperty -Name "RecordTime" -Value $a.tostring("yyyy-MM-ddTHH:mm:ss")
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
                                If ($null -ne $ACLentry.ObjectAceType){
                                    [string]$StrOAType = $ACLentry.ObjectAceType
                                    $Translated = $ACLentry.ObjectAceType
                                    
                                    Foreach ($RightGuid in $using:GetAlistOfExtendedRights){
                                        [string]$strRGuid = "None"
                                        [string]$strRGuid = $RightGuid.ACETypeGuid
                                        
                                        If ($strRGuid -like "$StrOAType"){
                                        
                                        $Translated =  $RightGuid.PropName
                                        }
                                        Else{
                                                 
                                            
                                        }
                                        
                                        }  
                                }
                                Else{
                                    $Translated = ""
                                }
                                
                                    #endOFForEachLoop
                                $obj |Add-Member -MemberType NoteProperty -Name "ObjectAceTypeTranslated" -Value   $Translated
                                $obj |Add-Member -MemberType NoteProperty -Name "ObjectAceFlags" -Value $ACLentry.ObjectAceFlags
                                $obj |Add-Member -MemberType NoteProperty -Name "Owner" -Value $ownerValue
                                $Emptyarray += $obj
                                
                             
            
             }                   
             }
    #coomment above
        $Emptyarray | export-csv $using:logfilepath  -Force -NoTypeInformation -Append #moved out of low loop to be done once per user
            
        
            
        } 

         
         } -ThrottleLimit $TrottleProcCount -AsJob -UseNewRunspace  #Uses Number processors variable for throttle limit
         #endRegion Main Loop processing data
    
    
    
    
   
    $fsx = 2
    [int]$OriginalCountLeftJobs = (Get-job -IncludeChildJob -ChildJobState NotStarted |  Where-Object State -like "NotStarted" | Measure-Object).Count
    Do{
    $CountLeftJobs = Get-job -IncludeChildJob -ChildJobState NotStarted |  Where-Object State -like "NotStarted" | Measure-Object
    $fsx = $CountLeftJobs.Count
    
    
    $CountLeftJobsRunning = get-job -IncludeChildJob -ChildJobState Running |  Where-Object State -like "Running" | Measure-Object
    $FSXRunning = $CountLeftJobsRunning.Count
    
    
        If ($fsx -lt 2){
            
            If ($FSXRunning -gt 0){
           $fsx = $FSXRunning  #Setting $FSX number to a number of still running jobs so script does not finish before they all change status from Running to something else
           
        }
        }
        If ($OriginalCountLeftJobs -le 1){


        }
        Else {Write-Progress -Id 0 -Activity "Jobs left for processing $fsx" -Status "Progress:" -PercentComplete ($fsx/$OriginalCountLeftJobs*100)
        
        }
        Start-sleep -Seconds 10
        Get-job -State  Completed | Where-Object PSjobtypename -like "PSTaskJob" | Remove-job
    } While ($fsx -gt 1)

    $adsisearcher = $null
    } #endoffunction queryobjectsfromADmulti



Function processgetadobject {
    param(
    $Listofobjects
    )

#endof processgetadobject
}

#Start of MAIN process
#region begin Mainvariables


$Nameselection = Start-MenuNamingContext -namingcontextinfunction $namingcontext
$Global:GetAlistOfExtendedRights = Get-myExtendedRights


$Mydate =""
$Mydate = Get-Date -Format "yyyy-MM-dd-HH-mm"
[string]$PartionToAttach = ""

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
        $startCounter = Get-date
        

        #region begin newcode
        $LdapPatition = "LDAP://" + $PartionToAttach
         queryobjectsfromADmulti -ldappath $LdapPatition -logfilepath $SaveToFile -Tombstone $true

        #endregion

        }
    'n' {
        Clear-Host
        write-host "Retriving list of objects from $PartionToAttach "
        $startCounter = Get-date
        

        $LdapPatition = "LDAP://" + $PartionToAttach

        queryobjectsfromADmulti -ldappath $LdapPatition -logfilepath $SaveToFile -Tombstone $false


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
$endcounter = Get-Date
$TotalTime = $endcounter - $startCounter
write-host "finished in $TotalTime" 


