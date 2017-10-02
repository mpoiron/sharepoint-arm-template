configuration PrepareSharePointServer
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DnsServer,

        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointSetupUserAccountCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointFarmAccountCreds,

        [Int]$RetryCount = 30,
        [Int]$RetryIntervalSec = 60
    )

    Import-DscResource -ModuleName xComputerManagement, xActiveDirectory, xCredSSP, xDisk, xNetworking, cDisk

    $Interface = Get-NetAdapter | Where Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $Interface.Name

    $DomainCreds = New-Object System.Management.Automation.PSCredential("${DomainName}\$($AdminCreds.UserName)", $AdminCreds.Password)
    $FarmCreds = New-Object System.Management.Automation.PSCredential("${DomainName}\$($SharePointFarmAccountCreds.UserName)", $SharePointFarmAccountCreds.Password)
    $SPsetupCreds = New-Object System.Management.Automation.PSCredential("${DomainName}\$($SharePointSetupUserAccountCreds.UserName)", $SharePointSetupUserAccountCreds.Password)

    Disable-LoopbackCheck

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
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

		WindowsFeature RSAT-DNS
		{
			Ensure = "Present"
			Name = "RSAT-DNS-Server"
		}
		WindowsFeature RSAT-AD-AdminCenter
		{
			Ensure = 'Present'
			Name   = 'RSAT-AD-AdminCenter'
		}
		WindowsFeature RSAT-ADDS
		{
			Ensure = 'Present'
			Name   = 'RSAT-ADDS'
		}
		WindowsFeature RSAT-AD-PowerShell
		{
			Ensure = 'Present'
			Name   = 'RSAT-AD-PowerShell'
		}
		WindowsFeature RSAT-AD-Tools
		{
			Ensure = 'Present'
			Name   = 'RSAT-AD-Tools'
		}

        xWaitforDisk Disk2
        {
            DiskNumber = 2
            RetryIntervalSec =$RetryIntervalSec
            RetryCount = $RetryCount
        }
        cDiskNoRestart SPDataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
            DependsOn = "[xWaitforDisk]Disk2"
        }

        xDNSServerAddress DnsServerAddress
        {
            Address        = $DnsServer
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $DomainName
            DomainUserCredential= $DomainCreds
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

        xADUser CreateSetupAccount
        {
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $SharePointSetupUserAccountCreds.UserName
            Password =$SharePointSetupUserAccountCreds
            Ensure = "Present"
            DependsOn = "[xComputer]DomainJoin"
        }
        Group AddSetupUserAccountToLocalAdminsGroup
        {
            GroupName = "Administrators"
            Credential = $DomainCreds
            MembersToInclude = "${DomainName}\$($SharePointSetupUserAccountCreds.UserName)"
            Ensure="Present"
            DependsOn = "[xADUser]CreateSetupAccount"
        }
        xADUser CreateFarmAccount
        {
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $SharePointFarmAccountCreds.UserName
            Password =$FarmCreds
            Ensure = "Present"
            DependsOn = "[xComputer]DomainJoin"
        }
    }
}

function Disable-LoopbackCheck
{
    # See KB896861 for more information about why this is necessary.
    Write-Verbose -Message "Disabling Loopback Check ..."
    New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name 'DisableLoopbackCheck' -value '1' -PropertyType dword -Force | Out-Null
}