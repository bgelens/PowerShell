Add-Type -AssemblyName 'system.io.compression.filesystem'
Add-Type -Language CSharp @"
public class VMRoleScaleOutSettings{
    public string InitialInstanceCount;
    public string MaximumInstanceCount;
    public string MinimumInstanceCount;
    public string UpgradeDomainCount;
}
"@

function Get-VMRoleResourceDefinition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline,
                   ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (Test-Path -Path $_.fullname) {
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
    [CmdletBinding(DefaultParameterSetName='Windows')]
    param (
        [Parameter(Mandatory)]
        [String] $Name,

        [Parameter(Mandatory)]
        [String] $Destination
    )
    #this function will merge all files and creates a ResDefPKG
    Process {
        $TempDir = [System.IO.Path]::GetTempPath()
        $TempSkeletonDir = $TempDir + $Name
        New-Item -Path $TempDir -Name $Name -ItemType Directory -Force | Out-Null

    }
}

function New-VMRoleIntrinsicSettings {
    param (
        [Parameter(Mandatory)]
        $HardwareProfile,

        [Parameter(Mandatory)]
        $NetworkProfile,

        [Parameter(Mandatory)]
        $OperatingSystemProfile,

        [Parameter(Mandatory)]
        [VMRoleScaleOutSettings] $ScaleOutSettings,

        [Parameter(Mandatory)]
        $StorageProfile
    )
    #this function will generate the intrinsicsettings part of the resdef json
    Write-Output -InputObject $ScaleOutSettings
}

function New-VMRoleHardWareProfile {

}

function New-VMRoleNetworkProfile {

}

function New-VMRoleOperatingSystemProfile {
    [CmdletBinding(DefaultParameterSetName='Windows')]
    param (
        [Parameter(ParameterSetName='Windows')]
        [Switch] $Windows,

        [Parameter(ParameterSetName='Linux')]
        [Switch] $Linux
    )

    switch ($PSCmdlet.ParameterSetName) {
            'Windows' {}
            'Linux' {}
    }
}

function New-VMRoleScaleOutSettings {
    param (
        [int] $InitialInstanceCount = 1,

        [int] $MaximumInstanceCount = 5,

        [int] $MinimumInstanceCount = 1,

        [int] $UpgradeDomainCount = 1
    )
    $Properties = @{
        InitialInstanceCount = $InitialInstanceCount
        MaximumInstanceCount = $MaximumInstanceCount
        MinimumInstanceCount = $MinimumInstanceCount
        UpgradeDomainCount = $UpgradeDomainCount

    }
    $object = New-Object -TypeName VMRoleScaleOutSettings -Property $Properties
    Write-Output -InputObject $object
}

function New-VMRoleStorageProfile {

}

#Helper functions for pre WMF5
function Expand-Archive {
    param (
        [String] $Path,

        [String] $ExpandDir
    )

    Write-Verbose -Message "Expanding $Path into $ExpandDir"
    [io.compression.zipfile]::ExtractToDirectory($Path, $ExpandDir)
}

function New-Archive {
    param (
        [String] $Path,

        [String] $Destination
    )
    [io.compression.zipfile]::CreateFromDirectory($Path, $Destination)    
}

Export-ModuleMember -Function *-VMRole*