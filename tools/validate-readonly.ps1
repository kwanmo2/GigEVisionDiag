param([string]$Configuration = 'Release', [switch]$ProductCollection)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskExe = Join-Path $taskRoot "build\$Configuration\fnc_tests.exe"
$taskProduct = Join-Path $taskRoot "build\$Configuration\FetchNetworkConfig.exe"
if (-not (Test-Path -LiteralPath $taskExe)) { throw 'Build with BUILD_TESTING enabled first.' }
$taskAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($ProductCollection -and -not $taskAdmin) { throw 'ProductCollection requires an existing administrator console. This script does not elevate itself.' }
if ($ProductCollection -and -not (Test-Path -LiteralPath $taskProduct)) { throw 'Product executable is missing.' }
$taskResultRoot = Join-Path $taskRoot 'test-results'
New-Item -ItemType Directory -Force -Path $taskResultRoot | Out-Null
$taskTestDir = Join-Path $taskResultRoot ('readonly-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskTestDir | Out-Null
function Read-Configuration {
    $taskState = [ordered]@{}
    $taskReads = [ordered]@{
        adapters = { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object InterfaceGuid | Select-Object InterfaceGuid,Name,InterfaceDescription,MacAddress,DriverVersion,DriverDate }
        advanced = { Get-NetAdapterAdvancedProperty -IncludeHidden -AllProperties -ErrorAction Stop | Sort-Object InstanceID,RegistryKeyword | Select-Object InstanceID,RegistryKeyword,RegistryValue }
        power = { Get-NetAdapterPowerManagement -IncludeHidden -ErrorAction Stop | Sort-Object InstanceID | Select-Object InstanceID,AllowComputerToTurnOffDevice,DeviceSleepOnDisconnect,SelectiveSuspend,WakeOnMagicPacket,WakeOnPattern,ArpOffload,NSOffload }
        ip_policy = { Get-NetIPInterface -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,Dhcp,AutomaticMetric,InterfaceMetric,NlMtu,Forwarding,WeakHostSend,WeakHostReceive,RouterDiscovery,ManagedAddressConfiguration,OtherStatefulConfiguration }
        persistent_routes = { Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop | Sort-Object InterfaceIndex,DestinationPrefix,NextHop | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,Protocol }
        firewall_profiles = { Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Sort-Object Name | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules }
        firewall_rules = { Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Sort-Object InstanceID | Select-Object InstanceID,Enabled,Profile,Direction,Action,PolicyStoreSource,PolicyStoreSourceType }
        tcpip_registry = { Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction Stop | Sort-Object PSChildName | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop | Select-Object PSChildName,EnableDHCP,IPAddress,SubnetMask,DefaultGateway,NameServer,IPAutoconfigurationEnabled } }
        audit_policy = { $taskAudit = & "$env:SystemRoot\System32\auditpol.exe" /get /category:* 2>&1; if ($LASTEXITCODE -ne 0) { throw "Audit policy read failed: $LASTEXITCODE" }; $taskAudit | ForEach-Object { "$_" } }
    }
    foreach ($taskName in $taskReads.Keys) {
        try { $taskState[$taskName] = @{ status='ok'; values=@(& $taskReads[$taskName]) } }
        catch { $taskState[$taskName] = @{ status='unavailable'; error=$_.Exception.Message; error_id=$_.FullyQualifiedErrorId } }
    }
    return ($taskState | ConvertTo-Json -Depth 12 -Compress)
}
$taskBefore = Read-Configuration
Set-Content -LiteralPath (Join-Path $taskTestDir 'configuration-before.json') -Value $taskBefore -Encoding UTF8
$taskMetrics = $null
if ($ProductCollection) {
    $taskClock = [Diagnostics.Stopwatch]::StartNew()
    $taskProcess = Start-Process -FilePath $taskProduct -ArgumentList @('collect', '--output', ('"' + $taskTestDir + '"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskTestDir 'product-stdout.txt') -RedirectStandardError (Join-Path $taskTestDir 'product-stderr.txt')
    $taskPeakPrivate = 0L; $taskPeakWorking = 0L; $taskCpuSeconds = 0.0
    while (-not $taskProcess.HasExited) {
        try { $taskProcess.Refresh(); $taskPeakPrivate = [Math]::Max($taskPeakPrivate, $taskProcess.PrivateMemorySize64); $taskPeakWorking = [Math]::Max($taskPeakWorking, $taskProcess.WorkingSet64); $taskCpuSeconds = $taskProcess.TotalProcessorTime.TotalSeconds } catch { }
        if ($taskClock.Elapsed.TotalMinutes -ge 10) { $taskProcess.Kill(); $taskProcess.WaitForExit(); throw 'Owned product process exceeded the ten-minute lab limit. Existing artifacts are preserved.' }
        Start-Sleep -Milliseconds 250
    }
    $taskProcess.WaitForExit(); $taskProcess.Refresh(); $taskProductExit = $taskProcess.ExitCode; $taskClock.Stop()
    $taskMetrics = [ordered]@{ duration_seconds=$taskClock.Elapsed.TotalSeconds; parent_peak_private_bytes=$taskPeakPrivate; parent_peak_working_set_bytes=$taskPeakWorking; parent_cpu_seconds=$taskCpuSeconds; exit_code=$taskProductExit; note='Parent process samples only; child collectors, WMI providers, disk/network tracing and camera frame statistics need separate lab evidence.' }
    if ($taskProductExit -notin @(0,1)) { throw "Product collection failed: $taskProductExit. Artifacts are preserved." }
} else {
    & $taskExe --live-readonly $taskTestDir
    if ($LASTEXITCODE -ne 0) { throw 'Live API test or packaging failed.' }
}
$taskAfter = Read-Configuration
Set-Content -LiteralPath (Join-Path $taskTestDir 'configuration-after.json') -Value $taskAfter -Encoding UTF8
$taskSame = $taskBefore -ceq $taskAfter
$taskNote = [ordered]@{ configuration_equal=$taskSame; elevated=$taskAdmin; mode=$(if ($ProductCollection) {'product'} else {'test-api'}); tool_version=(& $taskProduct --version).Trim(); exe_sha256=(Get-FileHash -LiteralPath $taskProduct -Algorithm SHA256).Hash.ToLowerInvariant(); os_build=[Environment]::OSVersion.Version.ToString(); resource_samples=$taskMetrics; note='Only accessible configuration was compared. Dynamic counters/leases/cache are excluded. Concurrent external changes can cause differences. File/registry traces and camera load were not measured by this script.' }
Set-Content -LiteralPath (Join-Path $taskTestDir 'validation.json') -Value ($taskNote | ConvertTo-Json -Depth 5) -Encoding UTF8
$taskArchive = Get-ChildItem -LiteralPath $taskTestDir -Recurse -File -Filter 'diagnostics.zip' | Select-Object -First 1
if ($null -eq $taskArchive) { throw 'Live diagnostics ZIP was not generated.' }
python (Join-Path $PSScriptRoot 'verify_bundle.py') $taskArchive.FullName
if ($LASTEXITCODE -ne 0) { throw 'Independent bundle verification failed.' }
if (-not $taskAdmin) {
    $taskDirectoriesBefore = @(Get-ChildItem -LiteralPath $taskTestDir -Directory).Count
    & $taskProduct collect --output $taskTestDir
    if ($LASTEXITCODE -ne 3) { throw 'Product executable did not enforce administrator requirement.' }
    if (@(Get-ChildItem -LiteralPath $taskTestDir -Directory).Count -ne $taskDirectoriesBefore) { throw 'Administrator rejection created a result directory.' }
}
Write-Output "Validation artifacts: $taskTestDir"
if (-not $taskSame) { throw 'Accessible configuration changed during the test; inspect before/after files and concurrent activity.' }
Write-Output 'Accessible configuration unchanged; diagnostic bundle and administrator gate verified.'
