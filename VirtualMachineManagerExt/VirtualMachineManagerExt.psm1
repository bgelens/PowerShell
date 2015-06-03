function Get-CloudResourceExtensionDependency {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]  
        [String] $Name,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Version
    )

    Process {
        Get-CloudResource | %{
            if ($_.ResourceDefinition.ResourceExtensionReferences.ReferenceName -eq $Name -and $_.ResourceDefinition.ResourceExtensionReferences.Version -eq $Version) {
                $_
            }
        }
    }
}
#Get-CloudResourceExtension -Name RABO_W2012R2_BASE -Version 1.0.0.1 | Get-CloudResourceExtensionDependency
#Get-CloudResourceExtension | Get-CloudResourceExtensionDependency