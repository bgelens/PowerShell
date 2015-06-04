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

        [Switch] $IncludeJSON
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

            Expand-Archive -Path $Path -ExpandDir $ExpandDir

            Write-Verbose -Message 'Finding ResDef file and converting JSON to PSObject'
            $ResDefJSON = Get-ChildItem *.resdef -Path $ExpandDir | Get-Content | Out-String
            $ResDef = $ResDefJSON | ConvertFrom-Json
            if ($IncludeJSON) {
                Add-Member -InputObject $ResDef -MemberType NoteProperty -Name 'JSON' -Value $ResDefJSON -Force
            }

            Write-Verbose -Message "Removing expand directory: $ExpandDir"
            Remove-Item $ExpandDir -Force -Recurse

            Write-Output -InputObject $ResDef
        }
        catch {
            Write-Error -Message $_.exception.message -ErrorAction Continue
        }
        finally {
            if (Test-Path -Path $ExpandDir) {
                Write-Verbose -Message "Removing expand directory: $ExpandDir"
                Remove-Item $ExpandDir -Force -Recurse
            }
        }
    }
    End {

    }
}
#Get-VMRoleResourceDefinition -Verbose -ResourceDefinitionPackagePath .\import\RABO_PROD_W2012R2_DEV_1001.resdefpkg
#dir .\import -File | Get-VMRoleResourceDefinition -Verbose -IncludeJSON

function Get-VMRoleViewDefinition {
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

        [Switch] $IncludeJSON
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

            Expand-Archive -Path $Path -ExpandDir $ExpandDir

            Write-Verbose -Message 'Finding ViewDef file and converting JSON to PSObject'
            $ViewDefJSON = Get-ChildItem *.viewdef -Path $ExpandDir | Get-Content | Out-String
            $ViewDef = $ViewDefJSON | ConvertFrom-Json
            if ($IncludeJSON) {
                Add-Member -InputObject $ViewDef -MemberType NoteProperty -Name 'JSON' -Value $ViewDefJSON -Force
            }

            Write-Output -InputObject $ViewDef
        }
        catch {
            Write-Error -Message $_.exception.message -ErrorAction Continue
        }
        finally {
            if (Test-Path -Path $ExpandDir) {
                Write-Verbose -Message "Removing expand directory: $ExpandDir"
                Remove-Item $ExpandDir -Force -Recurse
            }
        }
    }
    End {

    }

}
#Get-VMRoleViewDefinition -Verbose -ResourceDefinitionPackagePath .\import\RABO_PROD_W2012R2_DEV_1001.resdefpkg
#dir .\import -File | Get-VMRoleViewDefinition -Verbose -IncludeJSON

function New-VMRoleResDefPKG {
    [CmdletBinding()]
    param (
        
    )
}

#Helper function for pre WMF5
function Expand-Archive {
    param (
        [String] $Path,

        [String] $ExpandDir
    )

    Write-Verbose -Message "Expanding $Path into $ExpandDir"
    [io.compression.zipfile]::ExtractToDirectory($Path, $ExpandDir)
}

Export-ModuleMember -Function *-VMRole*