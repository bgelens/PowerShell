ipmo C:\git\PowerShell\WapTenantPublicAPI\WapTenantPublicAPI.psd1
Remove-Module WapTenantPublicAPI

$creds = Get-Credential
$token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.bgelens.nl' -Verbose
#Get-WAPASPNetToken -Credential ben@bgelens.nl -URL https://wapauth.bgelens.nl -Verbose -Port 443
$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -Verbose -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Name 'Test'
$Subscription | Get-WAPGalleryVMRole
$GI = $Subscription | Get-WAPGalleryVMRole -Name DSCPullServerClient
$OSDisk = $GI | Get-WAPVMRoleOSDisk
$NW = $Subscription | Get-WAPVMNetwork -Name internal


#New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $Net -OutVariable 'props' -Interactive
$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Medium -VMNetwork $NW
$VMProps.VMRoleAdminCredential = 'Administrator:Welkom01'
$VMProps.DSCPullServerClientCredential = 'Domain\Certreq:password'
$VMProps.DSCPullServerClientConfigurationId = '7844f909-1f2e-4770-9c97-7a2e2e5677ae'

Get-WAPCloudService -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose -List
#Get-WAPCloudService -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose -List
New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -CloudServiceName 'Test2' -Port 443

#Remove-WAPCloudService -Name 'test2' -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $subscription.subscriptionID -Port 443
#'test' | New-WAPCloudService -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $subscription.subscriptionid -Port 443 -Verbose
#'Test','Test2'| Remove-WAPCloudService -Token $token -Subscription $Subscription.subscriptionid -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Force
$prop = new-object -TypeName psobject -Property @{
    CloudServiceName = 'TestDSC'
    Token = $Token
    UserId = $creds.UserName
    PublicTenantAPIUrl = 'https://api.bgelens.nl'
    Subscription = $Subscription.Subscription
    Port = 443
} 

$prop | Get-WAPVMRole
$Subscription | Get-WAPVMRole -CloudServiceName 'TestDSC'

$role=Get-WAPVMRole -Token $token -UserId $creds.UserName -CloudServiceName 'TestDSC' -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose
Get-WAPVMRole -Token $token -UserId $creds.UserName -CloudServiceName 'TestDSC' -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.Subscription -Port 443 -Verbose

<#tenantpublicapi requirements!
tenantpublicapi needs to be configured for HybridTenant mode
This will allow token based authentication
The tenantpublicapi by default does not have enough permissions in the database to function correctly
Missing execute permissions can be resolved with the following TSQL script

USE [Microsoft.MgmtSvc.Store]
GO
Grant Execute On Type::.mp.CoAdminTableType To mp_TenantAPI
Grant Execute On Object::mp.GetInvalidatedUserTokens to mp_TenantAPI

#>