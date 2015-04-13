Find-Package git.install | Install-Package -Force
Find-Package poshgit | Install-Package -Force
[System.Environment]::SetEnvironmentVariable('Path', $env:path + ';C:\Program Files (x86)\Git\bin', 'Machine')
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
$POSHGITProfile = (Get-ChildItem -Filter profile.example.ps1 -Path c:\tools -Recurse).FullName
if (!(Test-Path $profile.AllUsersAllHosts)) {
    New-Item $profile.AllUsersAllHosts | Out-Null
}
"`r`n. $POSHGITProfile" | Out-File -FilePath $profile.AllUsersAllHosts -Append -NoClobber -Encoding ascii
. $POSHGITProfile