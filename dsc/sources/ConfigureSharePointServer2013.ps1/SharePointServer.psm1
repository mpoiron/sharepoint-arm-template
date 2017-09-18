function DisableLoopbackCheck
{
    # See KB896861 for more information about why this is necessary.
    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Disabling Loopback Check ..."
    New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name 'DisableLoopbackCheck' -value '1' -PropertyType dword -Force | Out-Null
}

function AddSharePointPsSnapin
{
    $Host.Runspace.ThreadOptions = 'ReuseThread'
    Write-Verbose -Message "Loading SharePoint PowerShell Snapin ..."
    Add-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction Stop | Out-Null
}

function LoadConfiguration
{
    param
    (
        [parameter(Mandatory)]
        [string] $Configuration
    )
    try 
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 'Loading Configuration....'

        $Script:Configuration = ConvertFrom-Json $Configuration

        foreach ($role in $Script:Configuration.roles)
        {
            if ($role.type -eq 'application')
            {
                $Script:ApplicationServerConfig = $role
            }
            elseif ($role.type -eq 'web')
            {
                $Script:WebServerConfig = $role
            }
            else
            {
                Write-Verbose -Message "Unsupported role type '$($role.type)' detected in configuration."
            }
        }

        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 'Finished Loading Configuration'
    }
    catch
    {
        Write-Warning ("Error:" + $_)
        throw 'Error Loading Configuration'
    }
}
function CheckIfJoinedFarm
{
    param
    (
        [parameter(Mandatory)]
        [string] $DatabaseName,

        [parameter(Mandatory)]
        [string] $DatabaseServer,

        [parameter(Mandatory)]
        [string] $AdministrationContentDatabaseName,

        [parameter(Mandatory)]
        [PSCredential] $FarmCredentials,

        [parameter(Mandatory)]
        [PSCredential] $Passphrase
    )

    try
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Testing if '$($env:COMPUTERNAME)' is a member of a farm ..."
        $spFarm = Get-SPFarm | Where-Object { $_.Name -eq $DatabaseName } -ErrorAction SilentlyContinue
    }
    catch
    { 
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "'$($env:COMPUTERNAME)' is not a member of a farm."
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 ("Error:" + $_)
    }

    if ($spFarm)
    {
        return $true
    }

    return $false
}

function CreateNewOrJoinExistingFarm
{
    param
    (
        [parameter(Mandatory)]
        [string] $DatabaseName,

        [parameter(Mandatory)]
        [string] $DatabaseServer,

        [parameter(Mandatory)]
        [string] $AdministrationContentDatabaseName,

        [parameter(Mandatory)]
        [PSCredential] $FarmCredentials,

        [parameter(Mandatory)]
        [PSCredential] $Passphrase
    )

    New-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -ea SilentlyContinue

    try
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Testing if '$($env:COMPUTERNAME)' is a member of a farm ..."
        $spFarm = Get-SPFarm | Where-Object { $_.Name -eq $DatabaseName } -ErrorAction SilentlyContinue
    }
    catch
    { 
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "'$($env:COMPUTERNAME)' is not a member of a farm."
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 ("Error:" + $_)
    }

    if (!$spFarm)
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Attempting to join farm '$($DatabaseName)' ..."
        $params = @{
            DatabaseName = $DatabaseName
            DatabaseServer = $DatabaseServer
            Passphrase = $Passphrase.GetNetworkCredential().SecurePassword
        }
        Connect-SPConfigurationDatabase @params -ErrorAction SilentlyContinue

        if (!$?)
        {
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Farm '$($DatabaseName)' does NOT exist."

            # This is to avoid a race condition between the previous
            # Connect-SPConfigurationDatabase call and upcoming
            # New-SPConfigurationDatabase call.
            Start-Sleep -Seconds 5

            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Creating farm '$($DatabaseName)' ..."
            $params = @{
                DatabaseName = $DatabaseName
                DatabaseServer = $DatabaseServer
                AdministrationContentDatabaseName = $AdministrationContentDatabaseName
                FarmCredentials = $FarmCredentials
                Passphrase = $Passphrase.GetNetworkCredential().SecurePassword
            }
            New-SPConfigurationDatabase @params

            if (!$?)
            {
                throw "Error creating farm."
            }
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully created farm '$($DatabaseName)'."
        }
        else
        {
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully joined farm '$($DatabaseName)'."
        }
    }
    else
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "'$($env:COMPUTERNAME)' is already a member of farm '$($DatabaseName)'."
    }
}

function ScanFarmServers
{
    param
    (
        [parameter(Mandatory)]
        [string] $DatabaseName,

        [parameter(Mandatory)]
        [string] $DatabaseServer
    )

    # TODO: update this function to handle the unlikely case where the database
    #   is hosted locally on one of the servers in the farm.
    $spFarm = Get-SPFarm | Where-Object { $_.Name -eq $DatabaseName }
    if ($spFarm.Servers.Count -gt 2)
    {
        $Script:IsFirstServer = $false
    }
    else
    {
        $Script:IsFirstServer = $true
    }
}

function ConfigureFarm
{
    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Configuring the farm ..."

    try
    {
        if ($Script:IsFirstServer)
        {
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Installing the Help site collection files ..."
            Install-SPHelpCollection -All
            if (!$?)
            {
                throw "Error installing the Help site collection files."
            }
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully installed the Help site collection files."
        }

        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Initializing resource security ..."
        Initialize-SPResourceSecurity
        if (!$?)
        {
            throw "Error initializing resource security."
        }
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully initialized resource security."

        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Installing and provisioning services ..."
        Install-SPService
        if (!$?)
        {
            throw "Error installing services."
        }
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully installed services."

        if ($Script:IsFirstServer)
        {
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Installing all existing SharePoint features ..."
            Install-SPFeature -AllExistingFeatures -Force | Out-Null
            if (!$?)
            {
                throw "Error installing all existing SharePoint features."
            }
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully installed all existing SharePoint features."
        }

        if ($Script:ApplicationServerConfig)
        {
            # Set up the Central Admin Web app only on application servers.
            # fqdn from NRP has a . at the end of the string
            $params = @{
                Fqdn = $Script:ApplicationServerConfig.properties.fqdn.TrimEnd('.')
                Port = $Script:ApplicationServerConfig.properties.port
            }
            CreateCentralAdministrationWebApp @params
        }

        if ($Script:IsFirstServer)
        {
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Copying shared application data to Web application folders ..."
            Install-SPApplicationContent
            if (!$?)
            {
                throw "Error copying shared application data."
            }
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully copied shared application data."

            # Enable ICMP echo for Distributed Cache.
            # See http://technet.microsoft.com/en-us/library/jj219572.aspx.
            Set-NetFirewallRule FPS-ICMP*-ERQ-In -Enabled True
        }
    }
    catch
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "An update conflict has occurred, retrying ..."
        ConfigureFarm
    }

    # Start/stop service instances based on the server role
    ConfigureServiceInstances

    if ($Script:Configuration.configureForHa -eq 'True')
    {
        $LoadBalancedSetProbePort = $Script:Configuration.loadBalancedSetProbePort

        # Repurpose the default web site for the Azure LBS probe.
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Setting the Port for the 'Default Web Site' to '$($LoadBalancedSetProbePort)' ..."
        Set-WebBinding -Name 'Default Web Site' -BindingInformation "*:80:" -PropertyName Port -Value $LoadBalancedSetProbePort

        $firewallRule=Get-NetFirewallRule -Name 'Azure-Load-Balanced-Set-Probe-HTTP-In' -ErrorAction SilentlyContinue 
        if ($firewallRule) 
        {
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Firewall rule for the load balanced set probe already exists..."
        }
        else
        {
            Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Adding a firewall rule for the load balanced set probe ..."
            New-NetFirewallRule -Direction Inbound `
                                -Name Azure-Load-Balanced-Set-Probe-HTTP-In `
                                -DisplayName "Azure Load Balanced Set Probe (HTTP-In)" `
                                -Description "Inbound rule for the Azure Load Balanced Set to allow HTTP traffic for its probe." `
                                -Group Azure `
                                -Enabled True `
                                -Action Allow `
                                -Protocol TCP `
                                -LocalPort $LoadBalancedSetProbePort `
                                | Out-Null
        }
    }

    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully configured the farm."
}

function TestCentralAdministrationWebApp
{
    param
    (
        [parameter(Mandatory)]
        [string] $Fqdn,

        [parameter(Mandatory)]
        [int] $Port
    )
    try {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Testing for an existing Central Administration Web application ..."
        $centralAdminServices = Get-SPServiceInstance | Where-Object { $_.TypeName -eq 'Central Administration' }
        $centralAdminServicesOnline = $centralAdminServices | Where-Object { $_.Status -eq 'Online' }
        $localCentralAdminService = $centralAdminServices | Where-Object { $_.Server.Address -eq $env:COMPUTERNAME }
        if ($localCentralAdminService.Status -ne 'Online')
        {
            return $false
        }
        else
        {
            return $true
        }
    }
    catch {
        if ($error[0]) {Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 $error[0].Exception}
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Testing for an existing Central Administration Web application ..."
    }

    return $false
}

function CreateCentralAdministrationWebApp
{
    param
    (
        [parameter(Mandatory)]
        [string] $Fqdn,

        [parameter(Mandatory)]
        [int] $Port
    )

    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Testing for an existing Central Administration Web application ..."
    $centralAdminServices = Get-SPServiceInstance | Where-Object { $_.TypeName -eq 'Central Administration' }
    $centralAdminServicesOnline = $centralAdminServices | Where-Object { $_.Status -eq 'Online' }
    $localCentralAdminService = $centralAdminServices | Where-Object { $_.Server.Address -eq $env:COMPUTERNAME }
    if ($localCentralAdminService.Status -ne 'Online')
    {
        try
        {
            if (!(Get-SPWebApplication -IncludeCentralAdministration | Where-Object { $_.IsAdministrationWebApplication }) -or $centralAdminServicesOnline.Count -lt 1)
            {
                Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "An existing Central Administration Web application was NOT found."
                Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Creating the Central Administration Web application ..."
                New-SPCentralAdministration -Port $Port -WindowsAuthProvider 'NTLM' -ErrorVariable errVar | Out-Null 
                if (!$?)
                {
                    throw "Error creating the Central Administration Web application."
                }
                Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully created the Central Administration Web application on port '$($Port)'."

                while ($localCentralAdminService.Status -ne 'Online')
                {
                    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Waiting for the Central Administration Web application on '$($env:COMPUTERNAME)' to come online ..."
                    Start-Sleep 5
                    $centralAdminServices = Get-SPServiceInstance | Where-Object { $_.TypeName -eq 'Central Administration' }
                    $localCentralAdminService = $centralAdminServices | Where-Object { $_.Server.Address -eq $env:COMPUTERNAME }
                }

                Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Configuring alternate URL for the Central Administration Web application ..."
                $centralAdminWebApp = Get-SPWebApplication -IncludeCentralAdministration | Where-Object { $_.IsAdministrationWebApplication }
		New-SPAlternateUrl -Url $("http://{0}:{1}" -f $Fqdn,$Port) -WebApplication $centralAdminWebApp -Zone Internet | Out-Null
		Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully configured alternate URL '$("http://{0}:{1}" -f $Fqdn,$Port)'."

                # TODO: set up an HTTPS binding for the central admin web app
                #Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Enabling SSL for the Central Administration Web application ..."
                #New-SPAlternateURL -Url $("https://{0}:{1}" -f $env:COMPUTERNAME,$Port) -WebApplication $localCentralAdminService -Zone Internet | Out-Null
            }
            else
            {
                Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "An existing Central Administration Web application was found."
                Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Creating a local Central Administration Web application ..."
                New-SPCentralAdministration | Out-Null
                Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully created the local Central Administration Web application."
            }
        }
        catch
        {
            if ($errVar -like "*update conflict*")
            {
                Write-Warning -EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 "An update conflict has occurred, retrying ..."
                CreateCentralAdministrationWebApp -Fqdn $Fqdn -Port $Port
            }
            else
            {
                throw "Error creating the Central Administration Web application: $_"
            }
        }
    }
    else
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Found an existing Central Administration Web application on '$($env:COMPUTERNAME)'."
    }
}

function ConfigureServiceInstances
{
    # By default, all servers will have the following services running:
    #   - Distributed Cache
    #   - Microsoft SharePoint Foundation Incoming E-Mail
    #   - Microsoft SharePoint Foundation Web Application
    #   - Microsoft SharePoint Foundation Workflow Timer Service
    # See also: http://technet.microsoft.com/en-us/library/jj219591(v=office.15).aspx#Section2.

    # SPTimerV4 isn't always running for the n+1 server
    $timersvc = Get-Service -Name 'SPTimerV4'
    if ($timersvc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped)
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Starting the $($timersvc.DisplayName) ... "
        Start-Service $timersvc
        if (!$?)
        {
            throw "Could not start the $($timersvc.DisplayName)."
        }
        $timersvc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running)
    }

    if ($Script:ApplicationServerConfig -and !$Script:WebServerConfig)
    {
        # The Central Admin service is configured in
        # CreateCentralAdministrationWebApp, so it's omitted here.

        $servicesToStop = @(
            'Microsoft SharePoint Foundation Incoming E-Mail'
            'Microsoft SharePoint Foundation Web Application'
        )
        $services = (Get-SPServer | Where-Object { $_.Name -eq $env:COMPUTERNAME }).ServiceInstances | Where-Object { $_.TypeName -in $servicesToStop -and ($_.Status -eq 'Online' -or $_.Status -eq 'Provisioning') }
        foreach ($service in $services)
        {
            Stop-SPServiceInstance $service -Confirm:$false | Out-Null
        }
    }

    if ($Script:WebServerConfig)
    {
        CreateFirstSite
    }
}

function CreateFirstSite
{
    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Creating web application '$($Script:WebServerConfig.properties.webApp.name)' ..."

    $ap = New-SPAuthenticationProvider
    $params = @{
        Name = $Script:WebServerConfig.properties.webApp.name
        ApplicationPool = $Script:WebServerConfig.properties.webApp.applicationPool
        ApplicationPoolAccount = $Script:WebServerConfig.properties.webApp.applicationPoolAccount
        URL = $Script:WebServerConfig.properties.webApp.url.TrimEnd('.')
        Port = $Script:WebServerConfig.properties.webApp.port
        HostHeader = $Script:WebServerConfig.properties.webApp.hostHeader.TrimEnd('.')
        DatabaseName = $Script:WebServerConfig.properties.webApp.databaseName
        AuthenticationProvider = $ap
    }
    if (Get-SPWebApplication | Where-Object { $_.DisplayName -eq $params.Name })
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Web application '$($params.Name)' already exists."
    }
    else
    {
        New-SPWebApplication @params -ErrorAction Stop | Out-Null
        if (!$?)
        {
            throw "Error creating web application '$($params.Name)'."
        }
    }
    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully created web application '$($params.Name)' at '$($params.URL)'."

    Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Creating site collection $($Script:WebServerConfig.properties.site.name) ..."

    $OwnerAliasDomain=(Get-NetBIOSName -DomainName $($Script:WebServerConfig.properties.site.ownerAliasDomain))
    $SecondaryOwnerAliasDomain=(Get-NetBIOSName -DomainName $($Script:WebServerConfig.properties.site.secondaryOwnerAliasDomain))

    $params = @{
        Name = $Script:WebServerConfig.properties.site.name
        Template = $Script:WebServerConfig.properties.site.template
        URL = $Script:WebServerConfig.properties.site.url.TrimEnd('.')
        OwnerAlias = "$OwnerAliasDomain\$($Script:WebServerConfig.properties.site.ownerAliasUserName)"
        SecondaryOwnerAlias = "$SecondaryOwnerAliasDomain\$($Script:WebServerConfig.properties.site.secondaryOwnerAliasUserName)"
    }
    if (Get-SPSite -Limit ALL | Where-Object { $_.Url -eq $params.URL })
    {
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Site collection '$($params.Name)' already exists."
    }
    else
    {
        New-SPSite @params -ErrorAction Stop | Out-Null
        if (!$?)
        {
            throw "Error creating site collection '$($params.Name)'."
        }
        Write-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "SharePointDeployment" -EventId 0 -Message "Successfully created site collection '$($params.Name)' at '$($params.URL)'."

        # TODO: If a template was specified, create default groups.
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
Export-ModuleMember -function *