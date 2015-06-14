Add-Type -AssemblyName 'system.io.compression.filesystem'

enum IPAllocationMethod {
    Dynamic
    Static
}

enum IPFamilyType {
    IPV4
    IPV6
}

class VMRoleDataVirtualHardDisk {
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [String] $DataVirtualHardDiskImage;

    [Parameter(Mandatory)]
    [ValidateRange(0,63)]
    [Int] $Lun;

    VMRoleDataVirtualHardDisk ([String] $DataVirtualHardDiskImage, [Int] $Lun) {
        $this.DataVirtualHardDiskImage = $DataVirtualHardDiskImage;
        $this.Lun = $Lun;    
    }
}

class VMRoleIPAddress {
    [Parameter(Mandatory)]
    [IPAllocationMethod] $AllocationMethod;

    [Parameter(Mandatory)]
    [IPFamilyType] $Type;

    [String] $ConfigurationName;

    VMRoleIPAddress ([IPAllocationMethod] $AllocationMethod, [IPFamilyType] $Type) {
        $this.AllocationMethod = $AllocationMethod;
        $this.Type = $Type;
        if ($type -eq 'IPV4') {
            $this.ConfigurationName = 'IPV4Configuration'
        } 
        else { 
            $this.ConfigurationName = 'IPV6 Address Configuration'
        }
    }

    VMRoleIPAddress ([IPAllocationMethod] $AllocationMethod, [IPFamilyType] $Type, [String] $ConfigurationName) {
        $this.AllocationMethod = $AllocationMethod;
        $this.Type = $Type;
        $this.ConfigurationName = $ConfigurationName;
    }
}

class VMRoleNetworkAdapter {
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [String] $Name;

    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [String] $NetworkRef;

    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [VMRoleIPAddress[]] $IPAddresses;

    VMRoleNetworkAdapter ([String] $Name, [String] $NetworkRef, [VMRoleIPAddress[]] $IPAddresses) {
        $this.Name = $Name;
        $this.NetworkRef = $NetworkRef;
        $this.IPAddresses = $IPAddresses;
    }
}

class VMRoleNetworkProfile {
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [VMRoleNetworkAdapter[]] $NetworkAdapters;

    VMRoleNetworkProfile ([VMRoleNetworkAdapter[]] $NetworkAdapters) {
        $this.NetworkAdapters = $NetworkAdapters
    }
}

class VMRoleHardWareProfile {
    [String] $VMSize;

    VMRoleHardWareProfile ([String] $VMSize) {
        $this.VMSize = $VMSize;
    }

    VMRoleHardWareProfile () {
        $this.VMSize = '[Param.VMRoleVMSize]'
    }
}

class VMRoleScaleOutSettings {
    [Parameter(Mandatory)]
    [ValidateRange(1,100)]
    [Int] $InitialInstanceCount;

    [Parameter(Mandatory)]
    [ValidateRange(1,100)]
    [Int] $MaximumInstanceCount;

    [Parameter(Mandatory)]
    [ValidateRange(1,100)]
    [Int] $MinimumInstanceCount;

    [Parameter(Mandatory)]
    [ValidateRange(1,10)]
    [Int] $UpgradeDomainCount;

    VMRoleScaleOutSettings ([Int] $InitialInstanceCount, [Int] $MaximumInstanceCount, [Int] $MinimumInstanceCount, [Int] $UpgradeDomainCount) {
        $this.InitialInstanceCount = $InitialInstanceCount;
        $this.MaximumInstanceCount = $MaximumInstanceCount;
        $this.MinimumInstanceCount = $MinimumInstanceCount;
        $this.UpgradeDomainCount = $UpgradeDomainCount;
    }
}

class VMRoleStorageProfile {
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [String] $OSVirtualHardDiskImage;

    [VMRoleDataVirtualHardDisk[]] $DataVirtualHardDisk;

    VMRoleStorageProfile ([String] $OSVirtualHardDiskImage, [VMRoleDataVirtualHardDisk[]] $DataVirtualHardDisk) {
        $this.OSVirtualHardDiskImage = $OSVirtualHardDiskImage;
        $this.DataVirtualHardDisk = $DataVirtualHardDisk;
    }

    VMRoleStorageProfile ([String] $OSVirtualHardDiskImage) {
        $this.OSVirtualHardDiskImage = $OSVirtualHardDiskImage;
    }

    VMRoleStorageProfile () {
        $this.OSVirtualHardDiskImage = '[Param.VMRoleOSVirtualHardDiskImage]';
    }
}

class VMRoleIntrinsicSettings {
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [VMRoleHardWareProfile] $HardwareProfile;

    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [VMRoleScaleOutSettings] $ScaleOutSettings;

    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [VMRoleStorageProfile] $StorageProfile;

    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [VMRoleNetworkProfile] $NetworkProfile;

    VMRoleIntrinsicSettings ([VMRoleHardWareProfile] $HardwareProfile, [VMRoleScaleOutSettings] $ScaleOutSettings, [VMRoleStorageProfile] $StorageProfile, [VMRoleNetworkProfile] $NetworkProfile) {
        $this.HardwareProfile = $HardwareProfile;
        $this.ScaleOutSettings = $ScaleOutSettings;
        $this.StorageProfile = $StorageProfile;
        $this.NetworkProfile = $NetworkProfile;
    }
}

class VMRoleParameter {
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [String] $Name;

    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [String] $Description;

    [Parameter(Mandatory)]
    [ValidateSet('String','Int','Boolean','Credential','SecureString')]
    [String] $Type;

    VMRoleParameter ([String] $Name, [String] $Description, [String] $Type) {
        $this.Name = $Name;
        $this.Description = $Description;
        $this.Type = $Type;
    }
}

class VMRoleWindowsOperatingSystemProfile {
    [String] $WorkgroupName;



    VMRoleWindowsOperatingSystemProfile ([String] $WorkgroupName) {
        $this.WorkgroupName = $WorkgroupName;
    }
}

#Master class, add by method
class VMRoleResourceDefinition {
    [String] $Name;

    [String] $Publisher;

    [String] $Version;

    hidden [String] $SchemaVersion = '1.0';

    hidden [String] $Type = 'Microsoft.Compute\/VMRole\/1.0';

    [VMRoleParameter[]] $ResourceParameters;

    [VMRoleIntrinsicSettings] $IntrinsicSettings;

    VMRoleResourceDefinition ([String] $Name, [String] $Publisher, [String] $Version) {
        $this.Name = $Name
        $this.Publisher = $Publisher;
        $this.Version = $Version;
    }

    AddResourceParameter ([VMRoleParameter[]] $Parameter) {
        $this.ResourceParameters += $Parameter
    }

    AddIntrinsicSettings ([VMRoleIntrinsicSettings] $IntrinsicSettings) {
        $this.IntrinsicSettings = $IntrinsicSettings
    }
}

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

function New-VMRoleResourceDefinition {
    param (
        [Parameter(Mandatory)]
        [String] $Name,

        [Parameter(Mandatory)]
        [String] $Publisher,

        [Version] $Version = '1.0.0.0',

        [Parameter(Mandatory)]
        [VMRoleIntrinsicSettings] $IntrinsicSettings,

        [Parameter(Mandatory)]
        [VMRoleParameter[]] $ResourceParameters
    )
    $props = @{
        Name = $Name
        Publisher = $Publisher
        Version = $Version.ToString()
        IntrinsicSettings = $IntrinsicSettings
        SchemaVersion = '1.0'
        Type = 'Microsoft.Compute\/VMRole\/1.0'
        ResourceParameters = $ResourceParameters

    }
    New-Object -TypeName psobject -Property $props
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