

[CmdletBinding()]
param (
    [ValidateNotNullOrEmpty()]
    [string]$DomainName = $env:USERDOMAIN,

    [ValidateNotNullOrEmpty()]
    [string]$UserName = "*",

    [ValidateNotNullOrEmpty()]
    [datetime]$StartTime = (Get-Date).AddHours(-1)
)

Invoke-Command -ComputerName (

    [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((
        New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName))
    ).PdcRoleOwner.name

) {

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740;StartTime=$Using:StartTime} |
    Where-Object {$_.Properties[0].Value -like "$Using:UserName"} |
    Select-Object -Property TimeCreated, 
        @{Label='UserName';Expression={$_.Properties[0].Value}},
        @{Label='ClientName';Expression={$_.Properties[1].Value}}


}  |
Select-Object -Property TimeCreated, 'UserName', 'ClientName' | Export-Csv -Append "C:\Users\Public\Desktop\Lockoutlogs\LockoutLog.csv"