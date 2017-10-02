configuration PrepareSqlServer
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DnsServer,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SqlServerServiceAccountCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointSetupUserAccountCreds,
        [String]$DomainNetBiosName=(Get-NetBIOSName -DomainName $DomainName),

        [Int]$RetryCount = 30,
        [Int]$RetryIntervalSec = 60
    )

    Import-DscResource -ModuleName xActiveDirectory, xComputerManagement, xCredSSP, xDisk, xNetworking, xSql, xSQLServer, cDisk

    Wait-SqlSetup

    $Interface = Get-NetAdapter | Where Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $Interface.Name

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetBiosName}\$($AdminCreds.UserName)", $AdminCreds.Password)
    [System.Management.Automation.PSCredential]$SPSCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetBiosName}\$($SharePointSetupUserAccountCreds.UserName)", $SharePointSetupUserAccountCreds.Password)
    [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetBiosName}\$($SqlServerServiceAccountCreds.UserName)", $SqlServerServiceAccountCreds.Password)

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = "ApplyOnly"
            RebootNodeIfNeeded = $true
        }

        xCredSSP Server
        {
            Ensure = "Present"
            Role = "Server"
        }
        xCredSSP Client
        {
            Ensure = "Present"
            Role = "Client"
            DelegateComputers = "*.$Domain", "localhost"
        }

        xWaitforDisk Disk2
        {
            DiskNumber = 2
            RetryIntervalSec = $RetryIntervalSec
            RetryCount = $RetryCount
        }
        cDiskNoRestart SQLDataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
	        DependsOn="[xWaitForDisk]Disk2"
        }

        xWaitforDisk Disk3
        {
            DiskNumber = 3
            RetryIntervalSec = $RetryIntervalSec
            RetryCount = $RetryCount
        }
        cDiskNoRestart SQLLogDisk
        {
            DiskNumber = 3
            DriveLetter = "G"
            DependsOn="[xWaitForDisk]Disk3"
        }

        xFirewall DatabaseEngineFirewallRule
        {
            Direction = "Inbound"
            Name = "SQL-Server-Database-Engine-TCP-In"
            DisplayName = "SQL Server Database Engine (TCP-In)"
            Description = "Inbound rule for SQL Server to allow TCP traffic for the Database Engine."
            DisplayGroup = "SQL Server"
            State = "Enabled"
            Access = "Allow"
            Protocol = "TCP"
            LocalPort = "1433"
            Ensure = "Present"
        }

        xDnsServerAddress DnsServerAddress
        {
            Address        = $DnsServer
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = "IPv4"
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $DomainName
            DomainUserCredential= $AdminCreds
            RetryCount = $RetryCount
            RetryIntervalSec = $RetryIntervalSec
        }

        xComputer DomainJoin
        {
            Name = $env:COMPUTERNAME
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xADUser CreateSqlServerServiceAccount
        {
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $SqlServerServiceAccountCreds.UserName
            Password = $SQLCreds
            Ensure = "Present"
            DependsOn = "[xComputer]DomainJoin"
        }

        xSqlServer ConfigureSqlServer
        {
            InstanceName = $env:COMPUTERNAME
            SqlAdministratorCredential = $AdminCreds
            ServiceCredential = $SQLCreds
            MaxDegreeOfParallelism = 1
            FilePath = "F:\DATA"
            LogPath = "G:\LOG"
            DomainAdministratorCredential = $DomainCreds
            DependsOn = "[xADUser]CreateSqlServerServiceAccount"

        }

        xADUser CreateSharePointSetupAccount
        {
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $SharePointSetupUserAccountCreds.UserName
            Password = $SPSCreds
            Ensure = "Present"
            DependsOn = "[xComputer]DomainJoin"
        }

        xSqlLogin AddDomainAdminAccountToSysadminServerRole
        {
            Name = "${DomainNetBiosName}\$($AdminCreds.UserName)"
            LoginType = "WindowsUser"
            ServerRoles = "sysadmin"
            Enabled = $true
            Credential = $AdminCreds
            DependsOn = "[xSqlServer]ConfigureSqlServer"
        }
        xSqlLogin ConfigureSharePointSetupAccountSqlLogin
        {
            Name = "${DomainNetBiosName}\$($SharePointSetupUserAccountCreds.UserName)"
            LoginType = "WindowsUser"
            ServerRoles = "securityadmin","dbcreator"
            Enabled = $true
            Credential = $AdminCreds
            DependsOn = "[xADUser]CreateSharePointSetupAccount","[xSqlServer]ConfigureSqlServer"
        }
    }
}

function Get-NetBIOSName
{
    [OutputType([string])]
    param(
        [string]$DomainName
    )

    if ($DomainName.Contains('.')) {
        $length=$DomainName.IndexOf('.')
        if ( $length -ge 16) {
            $length=15
        }
        return $DomainName.Substring(0,$length)
    }
    else {
        if ($DomainName.Length -gt 15) {
            return $DomainName.Substring(0,15)
        }
        else {
            return $DomainName
        }
    }
}

function Wait-SqlSetup
{
    # Wait for SQL Server Setup to finish before proceeding.
    while ($true)
    {
        try
        {
            Get-ScheduledTaskInfo "\ConfigureSqlImageTasks\RunConfigureImage" -ErrorAction Stop
            Start-Sleep -Seconds 5
        }
        catch
        {
            break
        }
    }
}
