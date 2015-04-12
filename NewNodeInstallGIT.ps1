Find-Package git.install | Install-Package -Force
Find-Package poshgit | Install-Package -Force
[System.Environment]::SetEnvironmentVariable('Path', $env:path + ';C:\Program Files (x86)\Git\bin', 'Machine')
$env:path = [System.Environment]::GetEnvironmentVariable('Path')
$POSHGITProfile = (Get-ChildItem -Filter profile.example.ps1 -Path c:\tools -Recurse).FullName
if (!(Test-Path $profile.AllUsersAllHosts)) {
    New-Item $profile.AllUsersAllHosts | Out-Null
}
". $POSHGITProfile" | Out-File -FilePath $profile.AllUsersAllHosts -Append -NoClobber