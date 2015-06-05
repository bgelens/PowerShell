$scaleout = New-VMRoleScaleOutSettings
$HW = New-VMRoleHardWareProfile

$disk1 = [DataVirtualHardDisk]::new()
$disk1.DataVirtualHardDiskImage = 'MyDataDisk01'
$disk1.Lun = 1

$disk2 = [DataVirtualHardDisk]::new()
$disk2.DataVirtualHardDiskImage = 'MyDataDisk02'
$disk2.Lun = 2

$storageprofile = New-VMRoleStorageProfile -DataVirtualHardDisk @($disk1,$disk2)
$intrinsic = New-VMRoleIntrinsicSettings -HardwareProfile $HW -ScaleOutSettings $scaleout -StorageProfile $storageprofile
$Resdef = New-VMRoleResourceDefinition -Name TestRole -Publisher 'Ben Gelens' -IntrinsicSettings $intrinsic
$Resdef
$Resdef | ConvertTo-Json -Depth 7