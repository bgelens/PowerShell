$Headers = @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $creds.UserName
    }
    #https://<ServiceMgmt>:30004/subscriptions/<SubscriptionId> 
    $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
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

#https://msdn.microsoft.com/en-us/library/dn448694.aspx

    $URI = '{0}:{1}/subscriptions?api-version=2013-03' -f 'https://wap.gelens.int','30004'
    $subscriptions = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
    foreach ($s in $subscriptions) {
        $s.items.services
    }

    [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy


<#
Ideas:
-----------------
Split module in 3 parts:
    * Auth module
    * TenantPublicAPI module
    * AdminApi module
Create all relevant function for admin and tenant actions
    Tenant:
        * Get-WAPSubscription
        * New-WAPSubscription
        * Remove-WAPSubscription
        * Etc
    Admin:
        * Get-WAPAdminSubscription
        * ....
Create DSC resources
    Admin Resource:
        * Configure actions
    Tenant Resource
        * Deploy actions

Create Pester scrips
    * Modules
    * DSC Resources
#>