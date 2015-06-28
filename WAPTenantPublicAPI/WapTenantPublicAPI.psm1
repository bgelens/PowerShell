function IgnoreSLL {
	$Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
	$Compiler= $Provider.CreateCompiler()
	$Params = New-Object System.CodeDom.Compiler.CompilerParameters
	$Params.GenerateExecutable = $False
	$Params.GenerateInMemory = $True
	$Params.IncludeDebugInformation = $False
	$Params.ReferencedAssemblies.Add("System.DLL") > $null
	$TASource=@'
		namespace Local.ToolkitExtensions.Net.CertificatePolicy
		{
			public class TrustAll : System.Net.ICertificatePolicy
			{
				public TrustAll() {}
				public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
				{
					return true;
				}
			}
		}
'@ 
	$TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
	$TAAssembly=$TAResults.CompiledAssembly
        ## We create an instance of TrustAll and attach it to the ServicePointManager
	$TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}

function Get-WAPAdfsToken {
    [cmdletbinding(DefaultParameterSetName='Tenant')]
    param (
        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [Parameter(Mandatory)]
        [String] $URL,

        [Int] $Port = 443,

        [Parameter(ParameterSetName='Tenant')]
        [Switch] $Tenant,

        [Parameter(ParameterSetName='Admin')]
        [Switch] $Admin
    )

    if ($PSCmdlet.ParameterSetName -eq 'Tenant') {
        $applyTo = 'http://azureservices/TenantSite'
    }
    else {
        $applyTo = 'http://azureservices/AdminSite'
    }
    #http://virtualstation.azurewebsites.net/?p=4331
    $sendTo = '{0}:{1}/adfs/services/trust/13/usernamemixed' -f $URL,$Port
    $tokenType = 'urn:ietf:params:oauth:token-type:jwt'

    $xml = @"
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                xmlns:a="http://www.w3.org/2005/08/addressing"
                xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <s:Header>
        <a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>
        <a:To s:mustUnderstand="1">$sendTo</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
          <o:UsernameToken u:Id=" uuid-00000000-0000-0000-0000-000000000000-0">
            <o:Username>$($Credential.UserName)</o:Username>
            <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">$($Credential.GetNetworkCredential().Password)</o:Password>
          </o:UsernameToken>
        </o:Security>
      </s:Header>
      <s:Body>
        <trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
          <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <a:EndpointReference>
              <a:Address>$applyTo</a:Address>
            </a:EndpointReference>
          </wsp:AppliesTo>
          <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>
          <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
          <trust:TokenType>$tokenType</trust:TokenType>
        </trust:RequestSecurityToken>
      </s:Body>
    </s:Envelope>
"@

    $tokenresponse = [xml] ($xml | Invoke-WebRequest -uri $sendto -Method Post -ContentType 'application/soap+xml' -TimeoutSec 30 -UseBasicParsing)

    $tokenString = $tokenresponse.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.InnerText
    $token = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenString))
    Write-Output -InputObject $token
}

function Get-WAPASPNetToken {
    # PowerShell script to get security token from membership STS
    # Copyright (c) Microsoft Corporation. All rights reserved.
    # Function taken from WAP Examples 'C:\Program Files\Management Service\MgmtSvc-PowerShellAPI\Samples\Authentication\Get-TokenMembership.ps1'
    # Modified by Ben Gelens, Inovativ
    # Adjustments:
    # Changed username password parameters to credential
    # Remove mandatory clientrealm and added default value
    [CmdletBinding()]
    Param(
        #[Parameter(Mandatory=$true)][string]$username,
        #[Parameter(Mandatory=$true)][string]$password,
        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [ValidateSet('http://azureservices/TenantSite','http://azureservices/AdminSite')]
        [string] $clientRealm = 'http://azureservices/TenantSite',

        [switch] $allowSelfSignCertificates,

        [Parameter(Mandatory)]
        [string] $URL,

        [Int] $Port
    )

    if ($Port -eq $null -and $clientRealm -eq 'http://azureservices/TenantSite') {
        $Port = 30071
    }
    if ($Port -eq $null -and $clientRealm -eq 'http://azureservices/AdminSite') {
        $Port = 30072
    }

    try {
        Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
        Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    }
    catch {
        throw $_
    }

    try {
        $identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ($URL + ":$Port" + '/wstrust/issue/usernamemixed')

        $identityProviderBinding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode]::TransportWithMessageCredential)
        $identityProviderBinding.Security.Message.EstablishSecurityContext = $false
        $identityProviderBinding.Security.Message.ClientCredentialType = 'UserName'
        $identityProviderBinding.Security.Transport.ClientCredentialType = 'None'

        $trustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $identityProviderBinding, $identityProviderEndpoint
        $trustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrust13

        if ($allowSelfSignCertificates) {
            $certificateAuthentication = New-Object -TypeName System.ServiceModel.Security.X509ServiceCertificateAuthentication
            $certificateAuthentication.CertificateValidationMode = 'None'
            $trustChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = $certificateAuthentication
        }

        $trustChannelFactory.Credentials.SupportInteractive = $false
        $trustChannelFactory.Credentials.UserName.UserName = $Credential.UserName
        $trustChannelFactory.Credentials.UserName.Password = $Credential.GetNetworkCredential().Password

        $channel = $trustChannelFactory.CreateChannel()
        $rst = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityToken -ArgumentList ([System.IdentityModel.Protocols.WSTrust.RequestTypes]::Issue)
        $rst.AppliesTo = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.EndpointReference -ArgumentList $clientRealm
        $rst.TokenType = 'urn:ietf:params:oauth:token-type:jwt'
        $rst.KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer

        $rstr = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse

        $token = $channel.Issue($rst, [ref] $rstr);

        $tokenString = ([System.IdentityModel.Tokens.GenericXmlSecurityToken]$token).TokenXml.InnerText;
        $result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenString));
        return $result
    }
    catch {
        throw $_
    }
}

function Get-WAPSubscription {
    <#
    .SYNOPSIS
    Retrieves Tenant User Subscription from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves Tenant User Subscription from Azure Pack TenantPublic or Tenant API

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    Retrieve Tenant User Subscription from Azure Pack
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory)]
        [String] $Token,

        [Parameter(Mandatory)]
        [String] $UserId,

        [Parameter(Mandatory)]
        [String] $PublicTenantAPIUrl,

        [Int] $Port = 30006,

        [Parameter(Mandatory,
                   ParameterSetName='Name')]
        [String] $Name,

        [Parameter(Mandatory,
                   ParameterSetName='Id')]
        [String] $Id,

        [Parameter(Mandatory,
                   ParameterSetName='List')]
        [Switch] $List,

        [Switch] $IgnoreSSL
    )
    
    try {
        if ($IgnoreSSL) {
            Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
            #Change Certificate Policy to ignore
            $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
            IgnoreSLL
        }
        Write-Verbose 'Constructing Header'
        $Headers = @{
                Authorization = "Bearer $Token"
                'x-ms-principal-id' = $UserId
                Accept = 'application/json'
        }
        $Headers | Out-String | Write-Debug
        
        $URL = '{0}:{1}/subscriptions/' -f $PublicTenantAPIUrl,$Port        
        Write-Verbose "Constructed Subscription URI: $URI"

        $Subscriptions = Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get
        $Subs = @()
        if ($PSCmdlet.ParameterSetName -eq 'Name') {
            $S = $Subscriptions | ?{$_.SubscriptionName -eq $Name}
            if ($S -eq $null) {
                throw "No subscriptions found matching specified name: $Name"
            }
            $Subs += $S
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Id') {
            $S = $Subscriptions | ?{$_.SubscriptionId -eq $Id}
            if ($S -eq $null) {
                throw "No subscriptions found matching specified Id: $Id"
            }
            $Subs += $S
        }
        else {
            foreach ($S in $Subscriptions) {
                $Subs += $S
            }
        }
        foreach ($S in $Subs) {
            $props = [ordered]@{
                SubscriptionID = $S.SubscriptionID
                SubscriptionName = $S.SubscriptionName
                AccountAdminLiveEmailId = $S.AccountAdminLiveEmailId
                ServiceAdminLiveEmailId = $S.ServiceAdminLiveEmailId
                CoAdminNames = $S.CoAdminNames
                AddOnReferences = $S.AddOnReferences
                AddOns = $S.AddOns
                State = $S.State
                QuotaSyncState = $S.QuotaSyncState
                ActivationSyncState = $S.ActivationSyncState
                PlanId = $S.PlanId
            }
            $props += $PSBoundParameters
            $props.Remove('Verbose')
            $props.Remove('Debug')
            $props.Remove('IgnoreSSL')
            $props.Remove('List')
            $obj = New-Object -TypeName psobject -Property $props
            $obj.PSObject.TypeNames.Insert(0,'WAP.Subscription')
            Write-Output -InputObject $obj
        }
    }
    catch {
        Write-Error $_.exception.message
    }
    finally {
        #Change Certificate Policy to the original
        if ($IgnoreSSL) {
            [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
        }
    }
}

function Get-WAPGalleryVMRole {
    <#
    .SYNOPSIS
    Retrieves VM Role Gallery Items asigned to Tenant user Subscription from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves VM Role Gallery Items asigned to Tenant user Subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    Retrieve Tenant User Subscription from Azure Pack
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | Get-WAPGalleryVMRole
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionID')]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Parameter(ParameterSetName='List')]
        [Switch] $List,

        [Parameter(Mandatory,
                   ParameterSetName='Name')]
        [String] $Name,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSLL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/Gallery/GalleryItems/$/MicrosoftCompute.VMRoleGalleryItem?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed Gallery Item URI: $URI"

            $GalleryItems = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get 
            
            $GIs = @()
            foreach ($G in $GalleryItems) {
                $GIs += $G.value
            }
            if ($PSCmdlet.ParameterSetName -eq 'Name') {
                $GIs = $GIs | ?{$_.name -eq $Name}
            }
            foreach ($G in $GIs) {
               
                $GIResDEFUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$G.ResourceDefinitionUrl
                Write-Verbose -Message "Acquiring ResDef from URI: $GIResDEFUri"
                $ResDef = Invoke-RestMethod -Uri $GIResDEFUri -Headers $Headers -Method Get

                $GIViewDefUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$G.ViewDefinitionUrl
                Write-Verbose -Message "Acquiring ViewDef from URI: $GIResDEFUri"
                $ViewDef = Invoke-RestMethod -Uri $GIViewDefUri -Headers $Headers -Method Get
                
                $props = [ordered]@{
                    Name           = $G.Name
                    Publisher      = $G.Publisher
                    PublisherLabel = $G.PublisherLabel
                    Version        = $G.Version
                    Description    = $G.Description
                    Label          = $G.Label
                    PublishDate    = [datetime]$G.PublishDate
                    ResDef         = $ResDef
                    ViewDef        = $ViewDef
                }
                $PSBoundParameters.Remove('Name') | out-null
                $props += $PSBoundParameters
                $props.Remove('Verbose')
                $props.Remove('Debug')
                $obj = New-Object -TypeName psobject -Property $props
                $obj.PSObject.TypeNames.Insert(0,'WAP.GI.VMRole')
                Write-Output -InputObject $obj
            }
        }
        catch {
            Write-Error -Message $_.exception.message
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }

}

function Get-WAPVMRoleOSDisk {
    <#
    .SYNOPSIS
    Retrieves Available VMRole OS Disks based on Gallery Item from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves Available VMRole OS Disks based on Gallery Item from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $GI = $Subscription | Get-WAPGalleryVMRole -Name MyVMRole
    $GI | Get-WAPVMRoleOSDisk -Verbose
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [PSCustomObject] $ViewDef,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionID')]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSLL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualHardDisks' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed VHD URI: $URI"

            $Sections = $ViewDef.ViewDefinition.Sections
            $Categories = $Sections | %{$_.Categories}
            $OSDiskParam = $Categories | %{$_.Parameters} | Where-Object{$_.Type -eq 'OSVirtualHardDisk'}

            $Images = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($I in $Images.value) {
                $Tags = $I.tag
                if ((Compare-Object -ReferenceObject $Tags -DifferenceObject $OSDiskParam.ImageTags).SideIndicator -eq $null) {
                    if ($I.enabled -eq $false) {
                        continue
                    }
                    else {
                        $props = [ordered]@{
                            Name            = $I.Name
                            Enabled         = $I.Enabled
                            FamilyName      = $I.FamilyName
                            Release         = $I.Release
                            OperatingSystem = $I.OperatingSystem
                            Tag             = $I.Tag
                            AddedTime       = [datetime]$I.AddedTime
                            VHDType         = $I.VHDType
                        }
                        $PSBoundParameters.Remove('ViewDef')
                        $props += $PSBoundParameters
                        $props.Remove('Verbose')
                        $props.Remove('Debug')
                        $obj = New-Object -TypeName psobject -Property $props
                        $obj.PSObject.TypeNames.Insert(0,'WAP.GI.OSDisk')
                        Write-Output -InputObject $obj
                    }
                }
            }                
        }
        catch {
            Write-Error -Message $_.exception.message
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPVMNetwork {
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory)]
        [String] $Token,

        [Parameter(Mandatory)]
        [String] $UserId,

        [Parameter(Mandatory)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory)]
        [String] $Subscription,

        [Int] $Port = 30006,

        [Parameter(Mandatory,
                   ParameterSetName='List')]
        [Switch] $List,

        [Parameter(Mandatory,
                   ParameterSetName='Name')]
        [String] $Name
    )

    $Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $UserId
    }

    $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMNetworks' -f $PublicTenantAPIUrl,$Port,$Subscription
    $VMNets = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
    
    foreach ($N in $VMNets.content.properties) {
        if ($PSCmdlet.ParameterSetName -eq 'Name' -and $N.Name -ne $Name) {
            continue
        }
        $Output = [pscustomobject]@{}
        Add-Member -InputObject $Output -MemberType NoteProperty -Name Name -Value $N.Name -Force
        Add-Member -InputObject $Output -MemberType NoteProperty -Name IsolationType -Value $N.IsolationType -Force
        Add-Member -InputObject $Output -MemberType NoteProperty -Name Enabled -Value $N.Enabled -Force
        Write-Output -InputObject $Output
    }
}

function New-WAPVMRoleParameterObject {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [Object] $VMRole,

        [Parameter(Mandatory)]
        [Object] $OSDisk,

        [Parameter(Mandatory)]
        [ValidateSet('Small','A7','ExtraSmall','Large','A6','Medium','ExtraLarge')]
        [String] $VMRoleVMSize,

        [Parameter(Mandatory)]
        [Object] $VMNetwork,

        [Switch] $Interactive
    )
    $Sections = $VMRole.ViewDef.ViewDefinition.Sections
    $Categories = $Sections | %{$_.Categories}
    $ViewDefParams = $Categories | %{$_.Parameters}
    $Output = [pscustomobject]@{}
    foreach ($P in $ViewDefParams) {
        $p | Out-String | Write-Verbose
        if ($Interactive -and $P.type -eq 'option') {
            $values = ''
            foreach ($v in $P.OptionValues) {
                $Def = ($v | Get-Member -MemberType NoteProperty).Definition.Split(' ')[1].Split('=')
                $Friendly = $Def[1]
                $Value = $Def[0] 
                $values += $value + ','
            }
            $values = $values.TrimEnd(',')
            if ($P.DefaultValue) {
                if(($result = Read-Host "Press enter to accept default value $($P.DefaultValue) for $($P.Name). Valid entries: $values") -eq ''){
                    Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $P.DefaultValue -Force
                }
                else {
                    do {
                        $result = Read-Host "Enter one of the following entries: $values"
                    }
                    while (@($values.Split(',')) -notcontains $result)
                    Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
                }
            }
            else {
                do {
                    $result = Read-Host "Enter one of the following entries: $values"
                }
                while (@($values.Split(',')) -notcontains $result)
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
            }
        }
        elseif ($Interactive -and $P.type -eq 'Credential') {
            do {
                $result = Read-Host "Enter a credential for $($P.Name) in the format domain\username:password or username:password"
            }
            while ($result -notmatch '\w+\\+\w+:+\w+' -and $result -notmatch '\w+:+\w+')
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
        }
        elseif ($P.DefaultValue) {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $P.DefaultValue -Force
        }
        elseif ($P.Type -eq 'OSVirtualHardDisk') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value "$($OSDisk.FamilyName):$($OSDisk.Release)" -Force
        }
        elseif ($P.Type -eq 'VMSize') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $VMRoleVMSize -Force
        }
        elseif ($P.Type -eq 'Credential') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value 'domain\username:password' -Force
        }
        elseif ($P.Type -eq 'Network') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $($VMNetwork.Name) -Force
        }
        elseif ($Interactive) {
            $result = Read-Host "Enter a value for $($P.Name) of type $($P.Type)"
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
        }
        else {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $null -Force
        }
        
    }
    Write-Output -InputObject $Output
}

function Get-WAPCloudService {
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(ParameterSetName = 'List')]
        [Switch] $List,

        [Parameter(Mandatory,
                   ValueFromPipeline,
                   ParameterSetName = 'Name')]
        [String] $Name,

        [Parameter(Mandatory)]
        [String] $Token,

        [Parameter(Mandatory)]
        [String] $UserId,

        [Parameter(Mandatory)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory)]
        [String] $Subscription,

        [Int] $Port = 30006
    )
    begin {
        $Headers = @{
                Authorization = "Bearer $Token"
                'x-ms-principal-id' = $UserId
        }
    }
    process {
        $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription

        Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get | %{

            if ($PSCmdlet.ParameterSetName -eq 'Name') {
                if ($obj = ($_ | ?{$_.content.properties.Name -eq $Name}).content.properties) {
                    Write-Output -InputObject $obj
                }
            }
            else {
                $obj = $_.content.properties
                Write-Output -InputObject $obj
            }
        }
    }
}

function New-WAPCloudService {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $Token,

        [Parameter(Mandatory)]
        [String] $UserId,

        [Parameter(Mandatory)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory)]
        [String] $Subscription,

        [Parameter(Mandatory,
                   ValueFromPipeline)]
        [String] $Name,

        [Int] $Port = 30006
    )
    begin {
        $Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $UserId
        }
    }
    process {
        $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
        $URI | Write-Verbose
        $CloudServiceConfig = @{
            Name = $Name
            Label = $Name
        } | ConvertTo-Json -Compress
        $CloudService = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $CloudServiceConfig -ContentType 'application/json'
        Write-Output -InputObject ([pscustomobject]$CloudService.entry.content.properties)
    }
}

function Remove-WAPCloudService {
    [CmdletBinding(SupportsShouldProcess,
                   ConfirmImpact='High')]
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline,
                   ParameterSetName = 'Name')]
        [String] $Name,

        [Parameter(Mandatory)]
        [String] $Token,

        [Parameter(Mandatory)]
        [String] $UserId,

        [Parameter(Mandatory)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory)]
        [String] $Subscription,

        [Int] $Port = 30006,

        [Switch] $Force
    )
    begin {
        $Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $UserId
        }
    }
    process {
        $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
        $Exists = Invoke-RestMethod -Uri $URI -Method Get -Headers $Headers | ?{$_.content.properties.name -eq $name}
        if ($Force -or $PSCmdlet.ShouldProcess($Name)) {
            if ($Exists -ne $null) {
                $RemURI = '{0}:{1}/{2}/CloudServices/{3}?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$Name
                Invoke-RestMethod -Uri $RemURI -Method Delete -Headers $Headers
            }    
        }
    }
}

function New-WAPVMRoleDeployment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Object] $VMRole,

        [Parameter(Mandatory)]
        [Object] $ParameterObject,

        [Parameter(Mandatory)]
        [String] $Token,

        [Parameter(Mandatory)]
        [String] $UserId,

        [Parameter(Mandatory)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory)]
        [String] $Subscription,

        [Parameter(Mandatory)]
        [String] $CloudServiceName,

        [Int] $Port = 30006
    )

    $CloudServiceParams = $PSBoundParameters
    [void] $CloudServiceParams.Remove('VMRole')
    [void] $CloudServiceParams.Remove('ParameterObject')
    [void] $CloudServiceParams.Remove('CloudServiceName')
    [void] $CloudServiceParams.Add('Name',$CloudServiceName)
    $CloudServiceParams | Out-String | Write-Verbose
    $Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $UserId
    }

    #Test if cloudservice already exist
    try {
        if (Get-WAPCloudService @CloudServiceParams) {
            throw "Cloud Service with name $CloudServiceName already exists"
        }
    }
    catch {
        Write-Error -Message $_.exception.message -ErrorAction Stop
    }

    #create cloudservice
    try {
        New-WAPCloudService @CloudServiceParams | Out-Null
    }
    catch {
        Write-Error -Message $_.exception.message -ErrorAction Stop
    }

    #Add ResDefConfig JSON to Dictionary
    $ResDefConfig = New-Object 'System.Collections.Generic.Dictionary[String,Object]'
    $ResDefConfig.Add('Version',$VMRole.version)
    $ResDefConfig.Add('ParameterValues',($ParameterObject | ConvertTo-Json))

    # Set Gallery Item Payload Info
    $GIPayload = @{
        InstanceView = $null
        Substate = $null
        Name = $CloudServiceName
        Label = $CloudServiceName
        ProvisioningState = $null
        ResourceConfiguration = $ResDefConfig
        ResourceDefinition = $VMRole.ResDef
    }

    # Convert Gallery Item Payload Info To JSON
    $GIPayloadJSON = ConvertTo-Json $GIPayload -Depth 10

    $DeployUri = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$CloudServiceName
    # Deploy Gallery Item VM Role
    try {
        $Deploy = Invoke-RestMethod -Uri $DeployUri -Headers $Headers -Method Post -Body $GIPayloadJSON -ContentType 'application/json'
        Write-Output -InputObject ([pscustomobject]$Deploy.entry.content.properties)
    }
    catch {
        Write-Error -Message 'Deployment Failure' -Exception $_.exception -ErrorAction Continue
        Remove-WAPCloudService @CloudServiceParams -Force | Out-Null
    }
}

function Get-WAPVMRole {
    <#
    .SYNOPSIS
    Retrieves Deployed VM Role information from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves Deployed VM Role information from Azure Pack TenantPublic or Tenant API.

    .PARAMETER CloudServiceName 
    The name of the cloud service where the VM Role is deployed to.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    Retrieve VM Role information from cloudservice 'Test' using custom api port 443
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    Get-WAPVMRole -Token $token -UserId $creds.UserName -CloudServiceName 'Test' -PublicTenantAPIUrl $URL -Subscription $Subscription.SubscriptionID -Port 443
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $CloudServiceName,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSLL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$CloudServiceName
            Write-Verbose "Constructed VMRole URI: $URI"

            $VMRole = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
        
            $VMRoleName = $VMRole.value.Name
            $URI = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles/{4}/VMs?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$CloudServiceName,$VMRoleName
            Write-Verbose "Constructed VMRole VMs URI: $URI"

            [PSObject[]] $VMs = @()
            Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get | %{
                $value = $_.value
                $IPs = foreach ($IP in $value.connectToAddresses) {
                    $IP = @{
                        IPAddress = $IP.IPAddress
                        Network   = $IP.NetworkName
                    }
                    New-Object -TypeName psobject -Property $IP
                }
                $vmparams = [ordered]@{
                    Id = $value.Id
                    ComputerName = $value.ComputerName
                    RuntimeState = $value.RuntimeState
                    IPAddresses  = $IPs
                }
                $VMs += (New-Object -TypeName psobject -Property $vmparams)
            }

            $params = [ordered]@{
                Name = $VMRoleName
                Label = $VMRole.value.Label
                ProvisioningState    = $VMRole.value.ProvisioningState
                ParameterValues      = $VMRole.value.ResourceConfiguration.ParameterValues | ConvertFrom-Json
                GalleryItemName      = $VMRole.value.ResourceDefinition.Name
                GalleryItemVersion   = $VMRole.value.ResourceDefinition.Version
                GalleryItemPublisher = $VMRole.value.ResourceDefinition.Publisher
                StateMessages        = $VMRole.value.Substate.VMRoleMessages
                CurrentInstanceCount = $VMRole.value.InstanceView.InstanceCount
                MaxInstanceCount     = $VMRole.value.InstanceView.ResolvedResourceDefinition.IntrinsicSettings.ScaleOutSettings.MaximumInstanceCount
                MinInstanceCount     = $VMRole.value.InstanceView.ResolvedResourceDefinition.IntrinsicSettings.ScaleOutSettings.MinimumInstanceCount
                VMSize               = $VMRole.value.InstanceView.ResolvedResourceDefinition.IntrinsicSettings.HardwareProfile.VMSize
                VMs                  = $VMs
            }
            $params += $PSBoundParameters
            $params.Remove('Verbose')
            $params.Remove('Debug')
            $obj = New-Object -TypeName psobject -Property $params
            $obj.PSObject.TypeNames.Insert(0,'WAP.VMRole')
            Write-Output -InputObject $obj
        }
        catch {
            Write-Error -Message $_.exception.message
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

Export-ModuleMember *-WAP*