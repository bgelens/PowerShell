﻿ipmo C:\git\PowerShell\WapTenantPublicAPI\WapTenantPublicAPI.psd1
#Remove-Module WapTenantPublicAPI

#example deployment 1
$creds = Get-Credential
$token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.bgelens.nl' -Verbose
$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -Verbose -PublicTenantAPIUrl https://api.bgelens.nl -Port 443 -Name 'Test'
#$Subscription | Get-WAPGalleryVMRole
$GI = $Subscription | Get-WAPGalleryVMRole -Name DSCPullServerClient
$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
$NW = $Subscription | Get-WAPVMNetwork -Name internal
$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
$VMProps.VMRoleAdminCredential = 'Administrator:Welkom01'
$VMProps.DSCPullServerClientCredential = 'Domain\Certreq:password'
$VMProps.DSCPullServerClientConfigurationId = '7844f909-1f2e-4770-9c97-7a2e2e5677ae'
$Subscription | New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -CloudServiceName MyCloudService -Verbose

#example deployment 2
$creds = Get-Credential
Get-WAPASPNetToken -Credential ben@bgelens.nl -URL https://wapauth.bgelens.nl -Verbose -Port 443
$GI = $Subscription | Get-WAPGalleryVMRole -Name DSCPullServerClient
$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
$NW = $Subscription | Get-WAPVMNetwork -Name internal
$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
$VMProps.VMRoleAdminCredential = 'Administrator:Welkom01'
$VMProps.DSCPullServerClientCredential = 'Domain\Certreq:password'
$VMProps.DSCPullServerClientConfigurationId = '7844f909-1f2e-4770-9c97-7a2e2e5677ae'
$CS = $Subscription | New-WAPCloudService -Name MyCloudService
$CS | New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -Verbose

#example check and work with cloudservices
$Subscription | Get-WAPCloudService
$CS = $Subscription | New-WAPCloudService -Name test
$CS | Get-WAPCloudService
$CS | New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -Verbose

#remove cloudservice including VM Role
$CS = $Subscription | Get-WAPCloudService -Name Test
$CS | Remove-WAPCloudService

#remove all cloudservices 
$Subscription | Get-WAPCloudService | Remove-WAPCloudService -Force

#remove specified cloudservice
$Subscription | Get-WAPCloudService -Name Test | Remove-WAPCloudService -Force

#get more details about deployed all deployed VM roles
$Subscription | Get-WAPCloudService | Get-WAPVMRole | select *

#get more details about specific deployed VM Role
$Subscription | Get-WAPCloudService -Name test | Get-WAPVMRole | select *

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