Add-Type -AssemblyName 'system.io.compression.filesystem'

function Get-VMRoleResourceDefinition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline,
                   ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (Test-Path -Path $_.fullname){
                $true
            }
            elseif ($_ -like '.\*') {
                Test-Path (Resolve-Path $_)
            }
            
        })]
        [System.io.FileInfo] $ResourceDefinitionPackagePath,

        [Switch] $IncludeViewDefinition
    )
    Begin {
        
    }
    Process {
        if ($ResourceDefinitionPackagePath -like '.\*') {
            $ResourceDefinitionPackagePath = Get-Item (Resolve-Path $ResourceDefinitionPackagePath)
        }
        $Path = $ResourceDefinitionPackagePath.FullName
        $ResourceDefPKG = $ResourceDefinitionPackagePath.Name
        $TempDir = [System.IO.Path]::GetTempPath()
        $ExpandDir = Join-Path -Path $TempDir -ChildPath $ResourceDefinitionPackagePath.BaseName

        Write-Verbose -Message "Processing $ResourceDefinitionPackagePath"

        $ErrorActionPreference = 'Stop'

        try {
            Write-Verbose -Message "Checking if expand directory $ExpandDir already exits"
            if (Test-Path $ExpandDir) {
                Write-Verbose -Message 'Removing expand directory as it already exists'
                Remove-Item $ExpandDir -Recurse -Force
            }
            Write-Verbose -Message "Creating temp directory to expand ResDefPKG in: $ExpandDir"
            New-Item -Path $TempDir -Name $ResourceDefinitionPackagePath.BaseName -ItemType Directory | Out-Null

            Write-Verbose -Message "Expanding $ResourceDefPKG into $ExpandDir"
            [io.compression.zipfile]::ExtractToDirectory($Path, $ExpandDir)

            Write-Verbose -Message 'Finding ResDef file and converting JSON to PSObject'
            $ResDef = Get-ChildItem *.resdef -Path $ExpandDir | Get-Content | Out-String | ConvertFrom-Json

            if ($IncludeViewDefinition) {
                Write-Verbose -Message 'IncludeViewDefinition Switch enabled, adding ViewDef property'
                $ViewDef = Get-ChildItem *.viewdef -Path $ExpandDir | Get-Content | Out-String | ConvertFrom-Json
                Add-Member -InputObject $ResDef -Name ViewDef -Value $ViewDef -MemberType NoteProperty -Force
            }

            Write-Verbose -Message "Removing expand directory: $ExpandDir"
            Remove-Item $ExpandDir -Force -Recurse

            Write-Output -InputObject $ResDef
        }
        catch {
            Write-Error -Message $_.exception.message -ErrorAction Continue
        }
    }
    End {

    }
}
#Get-VMRoleResourceDefinition -Verbose -ResourceDefinitionPackagePath .\import\RABO_PROD_W2012R2_DEV_1001.resdefpkg -IncludeViewDefinition
#dir .\import -File | Get-VMRoleResourceDefinition -IncludeViewDefinition -Verbose