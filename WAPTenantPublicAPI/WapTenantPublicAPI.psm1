function Get-WAPAdfsToken {
    [cmdletbinding(DefaultParameterSetName='Tenant')]
    param (
        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [Parameter(Mandatory)]
        [String] $AdfsURL,

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
    $sendTo = '{0}:{1}/adfs/services/trust/13/usernamemixed' -f $AdfsURL,$Port
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

    $tokenresponse = [xml] ($xml | Invoke-WebRequest -uri $sendto -Method Post -ContentType 'application/soap+xml' -TimeoutSec 30 )

    $tokenString = $tokenresponse.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.InnerText
    $token = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenString))
    Write-Output -InputObject $token
}

function Get-WAPASPNetToken {
    # PowerShell script to get security token from membership STS over AD FS
    # Copyright (c) Microsoft Corporation. All rights reserved.
    # Function taken from WAP Examples 'C:\Program Files\Management Service\MgmtSvc-PowerShellAPI\Samples\Authentication\Get-TokenMembership.ps1'
    # Modified by Ben Gelens, Inovativ
    # Adjustments:
    # Changed username password parameters to credential
    # Added dev switch
    # Removed authsiteaddress parameter
    # Remove mandatory clientrealm and added default value
    [cmdletbinding()]
    Param(
        #[Parameter(Mandatory=$true)][string]$username,
        #[Parameter(Mandatory=$true)][string]$password,
        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [ValidateSet('http://azureservices/TenantSite','http://azureservices/AdminSite')]
        [string] $clientRealm = 'http://azureservices/TenantSite',

        [switch] $allowSelfSignCertificates,

        [Parameter(Mandatory)]
        [string] $authSiteAddress
    )

    try {
        Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
        Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    }
    catch {
        throw $_
    }

    try {
        $identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ($authSiteAddress + '/wstrust/issue/usernamemixed')

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
    [cmdletbinding()]
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
                   ParameterSetName='List')]
        [Switch] $List
    )

    $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
    try {
        #Ignor error for self signed certificate

        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler = $Provider.CreateCompiler()
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add('System.DLL') > $null
        $TASource=@'
            namespace Local.ToolkitExtensions.Net.CertificatePolicy
            {
                public class TrustAll : System.Net.ICertificatePolicy
                {
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
            $TrustAll = $TAAssembly.CreateInstance('Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll')
            [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll

        $URL = '{0}:{1}/subscriptions/' -f $PublicTenantAPIUrl,$Port

        $Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $UserId
        }
        $Subscriptions = Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get
        foreach ($S in $Subscriptions) {
            if ($PSCmdlet.ParameterSetName -eq 'Name') {
                if ($sub = $S | Where-Object -FilterScript {$_.SubscriptionName -eq $name}) {
                    Write-Output -InputObject ([pscustomobject]$Sub)
                }
            }
            else {
                Write-Output -InputObject ([pscustomobject]$S)
            }
        }
    }
    catch {
        throw $_
    }
    finally {
        #Change Certificate Policy to the original
        [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy 
    }
}

function Get-WAPGalleryVMRole {
    [cmdletbinding(DefaultParameterSetName='List')]
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

        [Parameter(ParameterSetName='List')]
        [Switch] $List,

        [Parameter(Mandatory,
                   ParameterSetName='Name')]
        [String] $Name
    )

    $Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $UserId
    }
    $URI = '{0}:{1}/{2}/Gallery/GalleryItems/$/MicrosoftCompute.VMRoleGalleryItem?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
    $GalleryItems = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get 
    if ($PSCmdlet.ParameterSetName -eq 'Name') {
        $Items = $GalleryItems.content.properties | Where-Object{$_.name -eq $Name}
    }
    else {
        $Items = $GalleryItems.content.properties
    }
    foreach ($G in $Items) {
        $output = [pscustomobject]@{}
        Add-Member -InputObject $output -MemberType NoteProperty -Name Name -Value $G.Name -Force
        Add-Member -InputObject $output -MemberType NoteProperty -Name Publisher -Value $G.Publisher -Force
        Add-Member -InputObject $output -MemberType NoteProperty -Name Version -Value $G.Version -Force
        Add-Member -InputObject $output -MemberType NoteProperty -Name Description -Value $G.Description -Force
        Add-Member -InputObject $output -MemberType NoteProperty -Name Label -Value $G.Label -Force
        Add-Member -InputObject $output -MemberType NoteProperty -Name PublishDate -Value ([datetime]$G.PublishDate.'#text') -Force
        
        $GIResDEFUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$G.ResourceDefinitionUrl
        $ResDef = Invoke-RestMethod -Uri $GIResDEFUri -Headers $Headers -Method Get
        Add-Member -InputObject $output -MemberType NoteProperty -Name ResDef -Value $ResDef -Force
        
        $GIViewDefUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$G.ViewDefinitionUrl
        $ViewDef = Invoke-RestMethod -Uri $GIViewDefUri -Headers $Headers d-Method Get
        Add-Member -InputObject $output -MemberType NoteProperty -Name ViewDef -Value $ViewDef -Force
        Write-Output -InputObject $output
    }
}

function Get-WAPVMRoleOSDisk {
    [CmdletBinding()]
    param (
        [Object] $VMRole,

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
    $Sections = $VMRole.ViewDef.ViewDefinition.Sections
    $Categories = $Sections | %{$_.Categories}
    $OSDiskParam = $Categories | %{$_.Parameters} | Where-Object{$_.Type -eq 'OSVirtualHardDisk'}
    #$OSDiskParam.ImageTags

    $Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $UserId
    }
    $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualHardDisks' -f $PublicTenantAPIUrl,$Port,$Subscription
    $Images = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get 
    $Images | % {
        $Tags = $_.content.properties.tag.getenumerator().'#text'
        if ($Tags -eq $null) {

        }
        elseif ((Compare-Object -ReferenceObject $Tags -DifferenceObject $OSDiskParam.ImageTags).SideIndicator -eq $null) {
            $Disk = $_.content.properties
            $Output = [pscustomobject]@{}
            #$DiskName = ($Disk.Name.split('.')| Where-Object{$_ -notlike 'vhd*'}) -join ''
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Enabled -Value $Disk.Enabled -Force
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Name -Value $Disk.Name -Force
            Add-Member -InputObject $Output -MemberType NoteProperty -Name FamilyName -Value $Disk.FamilyName -Force
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Release -Value $Disk.Release -Force
            Add-Member -InputObject $Output -MemberType NoteProperty -Name OperatingSystem -Value $Disk.OperatingSystem -Force
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Tag -Value $Tags -Force
            Add-Member -InputObject $Output -MemberType NoteProperty -Name AddedTime -Value ([datetime]$Disk.AddedTime.'#text') -Force
            Write-Output -InputObject $Output
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
        [PSCredential] $Credential,

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
                $Friendly = $Def[0]
                $Value = $Def[1] 
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
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)" -Force
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

Export-ModuleMember *-WAP*