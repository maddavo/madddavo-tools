$old = "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2024.11100.16009.0_x64__8wekyb3d8bbwe\AppxManifest.xml"

if (!(Test-Path $old)) {
    Write-Error "Old Photos package not found: $old"
    exit 1
}

Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage
Add-AppxPackage -DisableDevelopmentMode -Register $old

Get-AppxPackage Microsoft.Windows.Photos |
    Select-Object Name, Version, PackageFullName