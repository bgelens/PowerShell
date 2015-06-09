$ip1 = [VMRoleIPAddress]::new('Dynamic','IPV4')
$NIC1 = [VMRoleNetworkAdapter]::new('NIC1','[Param.VMRoleNetworkRef]',$ip1)
$NetProf = [VMRoleNetworkProfile]::new(@($NIC1))

$disk1 = [VMRoleDataVirtualHardDisk]::new('Data-100GB:1.0.0.0',0)
$disk2 = [VMRoleDataVirtualHardDisk]::new('Data-1TB:1.0.0.0',1)
$storageprof = [VMRoleStorageProfile]::new('[Param.VMRoleOSVirtualHardDiskImage]',@($disk1,$disk2))

$ScaleOut = [VMRoleScaleOutSettings]::new(1,10,2,2)

$HWProf = [VMRoleHardWareProfile]::new()

$OSDiskParam = [VMRoleParameter]::new('VMRoleOSVirtualHardDiskImage','VMRoleOSVirtualHardDiskImage','String')
$NetRefParam = [VMRoleParameter]::new('VMRoleNetworkRef','Network reference','String')

$intrinsic = [VMRoleIntrinsicSettings]::new($HWProf,$scaleout,$storageprof,$NetProf)
$Resdef = New-VMRoleResourceDefinition -Name TestRole -Publisher 'Ben Gelens' -IntrinsicSettings $intrinsic -ResourceParameters @($OSDiskParam,$NetRefParam)
$Resdef | ConvertTo-Json -Depth 7



#add by method (Master class)
$temp = [VMRoleResourceDefinition]::new('test','Ben','1.0.0.0') 
$temp.AddResourceParameter(@($OSDiskParam,$NetRefParam))