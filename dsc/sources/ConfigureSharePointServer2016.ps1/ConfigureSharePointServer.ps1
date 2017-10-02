configuration ConfigureSharePointServer
{

    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointSetupUserAccountCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointFarmAccountCreds,

        [parameter(Mandatory)]
        [String]$Configuration,

        [Int]$RetryCount=30,
        [Int]$RetryIntervalSec=60
    )

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }
    }
}