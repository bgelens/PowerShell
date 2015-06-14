$OSDiskParam = [VMRoleParameter]::new('VMRoleOSVirtualHardDiskImage','VMRoleOSVirtualHardDiskImage','String')
$NetRefParam = [VMRoleParameter]::new('VMRoleNetworkRef','Network reference','String')

$ip1 = [VMRoleIPAddress]::new('Dynamic','IPV4')
$NIC1 = [VMRoleNetworkAdapter]::new('NIC1','[Param.VMRoleNetworkRef]',$ip1)
$NetProf = [VMRoleNetworkProfile]::new(@($NIC1))

$disk1 = [VMRoleDataVirtualHardDisk]::new('Data-100GB:1.0.0.0',0)
$disk2 = [VMRoleDataVirtualHardDisk]::new('Data-1TB:1.0.0.0',1)
$disk3 = [VMRoleDataVirtualHardDisk]::new('Data-1GB:1.0.0.0',2)
$storageprof = [VMRoleStorageProfile]::new('[Param.VMRoleOSVirtualHardDiskImage]',@($disk1,$disk2,$disk3))

$ScaleOut = [VMRoleScaleOutSettings]::new(1,10,2,2)

$HWProf = [VMRoleHardWareProfile]::new()

$intrinsic = [VMRoleIntrinsicSettings]::new($HWProf,$scaleout,$storageprof,$NetProf)

$ResDef = [VMRoleResourceDefinition]::new('test','Ben','1.0.0.0') 
$ResDef.AddResourceParameter(@($OSDiskParam,$NetRefParam))
$Resdef.AddIntrinsicSettings($intrinsic)
$ResDef | ConvertTo-Json -Depth 7