ipmo C:\git\PowerShell\WapTenantPublicAPI\WapTenantPublicAPI.psd1
Remove-Module WapTenantPublicAPI

#$creds = Get-Credential
$token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.bgelens.nl' -Verbose

#Get-WAPASPNetToken -Credential ben@bgelens.nl -URL https://wapauth.bgelens.nl -Verbose -Port 443

#Get-WAPSubscription -Token $Token -UserId $creds.UserName -Verbose -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -List
$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -Verbose -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Name 'Test'

#Get-WAPGalleryVMRole -Token $token -UserId $creds.UserName -Subscription $Subscription.SubscriptionID -Verbose -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -List -OutVariable 't'
$GI = Get-WAPGalleryVMRole -Token $token -UserId $creds.UserName -Subscription $Subscription.SubscriptionID -Verbose -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Name DSCPullServerClient

$OSDisk = Get-WAPVMRoleOSDisk -VMRole $GI -Token $token -UserId $creds.UserName -Subscription $Subscription.SubscriptionID -Verbose `
                              -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 | Sort-Object Addedtime -Descending | Select-Object -First 1

#Get-WAPVMNetwork -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Verbose -Subscription $Subscription.SubscriptionID -List
$Net = Get-WAPVMNetwork -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Verbose -Subscription $Subscription.SubscriptionID -Name Internal

#New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $Net -OutVariable 'props' -Interactive
$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Medium -VMNetwork $Net
$VMProps.VMRoleAdminCredential = 'Administrator:Welkom01'
$VMProps.DSCPullServerClientCredential = 'Domain\Certreq:password'
$VMProps.DSCPullServerClientConfigurationId = '7844f909-1f2e-4770-9c97-7a2e2e5677ae'

Get-WAPCloudService -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose -List
#Get-WAPCloudService -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose -List
New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -CloudServiceName 'Test2' -Port 443

#Remove-WAPCloudService -Name 'test2' -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $subscription.subscriptionID -Port 443
#'test' | New-WAPCloudService -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $subscription.subscriptionid -Port 443 -Verbose
#'Test','Test2'| Remove-WAPCloudService -Token $token -Subscription $Subscription.subscriptionid -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Force

$role=Get-WAPDeployedVMRole -Token $token -UserId $creds.UserName -CloudServiceName 'TestDSC' -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose 
Get-WAPDeployedVMRoleVM -Token $token -UserId $creds.UserName -CloudServiceName 'TestDSC' -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose -VMRoleName 'TestDSC'
Get-WAPDeployedVMRoleVM -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.bgelens.nl -Subscription $Subscription.SubscriptionID -Port 443 -Verbose -DeployedVMRole $role
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