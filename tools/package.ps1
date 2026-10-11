param([string]$Configuration = 'Release', [switch]$RequireSignature, [string]$ValidationRecord)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskBinary = Join-Path $taskRoot "build\$Configuration\FetchNetworkConfig.exe"
if (-not (Test-Path -LiteralPath $taskBinary)) { throw 'Build the executable before packaging.' }
$taskVersion = (& $taskBinary --version).Trim()
if ($LASTEXITCODE -ne 0 -or $taskVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Cannot read executable version.' }
$taskDist = Join-Path $taskRoot 'dist'
$taskPackage = Join-Path $taskDist "FetchNetworkConfig-$taskVersion-win-x64"
$taskZip = "$taskPackage.zip"
if (Test-Path -LiteralPath $taskPackage) { throw "Package directory already exists; use a new release location: $taskPackage" }
if (Test-Path -LiteralPath $taskZip) { throw "Archive already exists: $taskZip" }
$taskSignature = Get-AuthenticodeSignature -LiteralPath $taskBinary
if ($RequireSignature -and $taskSignature.Status -ne 'Valid') { throw 'A valid code signature is required for this packaging run.' }
if ($taskSignature.Status -notin @('Valid', 'NotSigned')) { throw "Invalid or untrusted signature: $($taskSignature.Status)" }
$taskMetadata = (Get-Item -LiteralPath $taskBinary).VersionInfo
if ($taskMetadata.ProductVersion -ne $taskVersion -or [string]::IsNullOrWhiteSpace($taskMetadata.CompanyName)) { throw 'Executable version/publisher metadata is missing or mismatched.' }
$taskBinaryHash = (Get-FileHash -LiteralPath $taskBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$taskValidation = $null
if ($ValidationRecord) {
    $taskValidation = Get-Content -LiteralPath $ValidationRecord -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($taskValidation.schema_version -ne 1 -or $taskValidation.tool_version -ne $taskVersion -or $taskValidation.exe_sha256 -ne $taskBinaryHash) { throw 'Environment validation must reference this exact executable.' }
    foreach ($taskCheck in @('administrator_before_after', 'windows10_compatibility', 'windows11_compatibility', 'camera_load', 'runtime_access_trace', 'customer_policy')) {
        if ($taskValidation.completed_checks.$taskCheck -isnot [bool] -or $taskValidation.completed_checks.$taskCheck -ne $true) { throw "Environment validation is incomplete: $taskCheck" }
    }
}
New-Item -ItemType Directory -Path $taskPackage -Force | Out-Null
Copy-Item -LiteralPath $taskBinary -Destination $taskPackage
Copy-Item -LiteralPath (Join-Path $taskRoot 'docs\CUSTOMER_GUIDE.md') -Destination (Join-Path $taskPackage 'README.md')
New-Item -ItemType Directory -Path (Join-Path $taskPackage 'docs'),(Join-Path $taskPackage 'licenses') | Out-Null
Copy-Item -LiteralPath (Join-Path $taskRoot 'docs\READ_ONLY_CONTRACT.md') -Destination (Join-Path $taskPackage 'docs')
Copy-Item -LiteralPath (Join-Path $taskRoot 'docs\RELEASE_NOTES.md') -Destination (Join-Path $taskPackage 'docs')
Copy-Item -LiteralPath (Join-Path $taskRoot 'third_party\NOTICE.md') -Destination (Join-Path $taskPackage 'licenses')
Copy-Item -LiteralPath (Join-Path $taskRoot 'third_party\json\LICENSE.MIT') -Destination (Join-Path $taskPackage 'licenses\json-LICENSE.MIT')
Copy-Item -LiteralPath (Join-Path $taskRoot 'third_party\miniz\LICENSE') -Destination (Join-Path $taskPackage 'licenses\miniz-LICENSE.txt')
Set-Content -LiteralPath (Join-Path $taskPackage 'FetchNetworkConfig.exe.sha256') -Value "$taskBinaryHash  FetchNetworkConfig.exe" -Encoding ASCII
$taskStatus = [ordered]@{ schema_version=1; tool_version=$taskVersion; exe_sha256=$taskBinaryHash; signature_status=[string]$taskSignature.Status; file_version=$taskMetadata.FileVersion; publisher_display_name=$taskMetadata.CompanyName; environment_validation=$(if ($null -eq $taskValidation) {'pending'} else {'provided'}); note='Publisher display metadata is not a digital signature. Internal validation records and customer evidence are excluded.' }
Set-Content -LiteralPath (Join-Path $taskPackage 'RELEASE_STATUS.json') -Value ($taskStatus | ConvertTo-Json -Depth 5) -Encoding UTF8
Compress-Archive -LiteralPath $taskPackage -DestinationPath $taskZip
$taskZipHash = (Get-FileHash -LiteralPath $taskZip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$taskZip.sha256" -Value "$taskZipHash  $(Split-Path -Leaf $taskZip)" -Encoding ASCII
python (Join-Path $PSScriptRoot 'verify_package.py') $taskZip
if ($LASTEXITCODE -ne 0) { throw 'Final package verification failed; do not distribute this archive.' }
Write-Output $taskZip
