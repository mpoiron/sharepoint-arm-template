﻿configuration CreateADPDC
{
   param
   (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )

    Import-DscResource -ModuleName xActiveDirectory, xCredSSP, xDisk, xNetworking, cDisk

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

    $Interface = Get-NetAdapter | Where Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $Interface.Name

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

        WindowsFeature DNS
        {
            Ensure = "Present"
            Name = "DNS"
        }
        WindowsFeature DnsTools
        {
            Ensure = "Present"
            Name = "RSAT-Dns-Server"
            DependsOn = "[WindowsFeature]DNS"
        }
        xDnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1'
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
	        DependsOn = "[WindowsFeature]DNS"
        }

        xWaitforDisk Disk2
        {
             DiskNumber = 2
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
        }
        cDiskNoRestart ADDataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
	        DependsOn="[xWaitForDisk]Disk2"
        }

        WindowsFeature ADDSInstall
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[cDiskNoRestart]ADDataDisk"
        }
        WindowsFeature ADDSTools
        {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        xADDomain FirstDS
        {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath = "F:\NTDS"
            LogPath = "F:\NTDS"
            SysvolPath = "F:\SYSVOL"
	        DependsOn="[WindowsFeature]ADDSInstall"
        }

        xADDomainDefaultPasswordPolicy PasswordPolicy
        {
            DomainName = $DomainName
            ComplexityEnabled = $true
            MinPasswordAge = 0
            MaxPasswordAge = 0
            LockoutDuration = 0
            LockoutObservationWindow = 0
        }
   }
}