# Project
This project was put together in order to offer a solution that easily exports Active Directory 
security permissions into a format that may be saved into an Azure Log Analytics workspace, 
or other security database for later review or investigation.

## Usage

.\Export-ADPermissionsData.ps1 -namingcontext \<string\> -includedeletedobjects \<string\> -outputfile \<string\>

#### -namingcontext
    
The parameter namingcontext is used to define the naming context to search
An example would be "DC=contoso,DC=com" or you could use OU path like this "OU=accounts,DC=contoso,DC=com"

#### -includedeletedobjects
    
The parameter includedeletedobjects is used to define if Deleted objects should be searched or not.
Options are "y", "n", "c" for cancel script.

#### -outputfile
    
The parameter outputfile is used to define path where the CSV file is saved. This is optional, if 
ommitted script will save file to the location of your powershell location session with the prefix 
"Permissions_" and then the domain name and a timestamp of execution.

### Examples  
The example below exports permission information on deleted objects only.
    
    .\Export-ADPermissionsData.ps1 -namingcontext "DC=contoso,DC=com" -includedeletedobjects "y"

Another example : if you run script with no paramaters, menu will appear allowing selection of context and 
if deleted objects should be included.
    
    .\Export-ADPermissionsData.ps1
  
## Issues 
If you find any bugs when using Export-ADPermissionsData, please file an issue in our [GitHub Issues](https://github.com/Azure/msft-ADPermissionAuditInAzure/issues) page.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
