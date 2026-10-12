<#
.SYNOPSIS
  Engineer-side AI review of a FetchNetworkConfig result (not shipped to customers).

.DESCRIPTION
  1. Runs "FetchNetworkConfig.exe analyze" to produce the rule-based report and the masked llm-context.json.
  2. Sends only llm-context.json to Codex CLI ("codex exec", using the engineer's ChatGPT sign-in).
  3. Validates the structured answer and re-runs analyze with --ai-review to embed it in analysis.html.

  The customer collector EXE itself never performs network access. This script is the only step that sends
  data outside the PC, and it sends the masked derived context, never raw logs or the evidence ZIP.

.EXAMPLE
  .\tools\ai-review.ps1 -Evidence D:\Cases\FetchNetworkConfig-...\diagnostics.zip -LogUtcOffset +09:00
#>
param(
    [Parameter(Mandatory = $true)][string]$Evidence,
    [string]$Exe,
    [string]$Output,
    [string]$LogUtcOffset,
    [string]$Model,
    [switch]$Yes
)
$ErrorActionPreference = 'Stop'

function Find-Exe {
    foreach ($candidate in @((Join-Path $PSScriptRoot 'FetchNetworkConfig.exe'),
                             (Join-Path (Split-Path -Parent $PSScriptRoot) 'build\Release\FetchNetworkConfig.exe'))) {
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    $command = Get-Command FetchNetworkConfig.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'FetchNetworkConfig.exe not found. Pass -Exe <path>.'
}

# Windows PowerShell 5.1 turns native stderr into terminating errors under 'Stop'; codex reports progress on stderr.
function Invoke-Native([scriptblock]$Block) {
    $previous = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; & $Block } finally { $ErrorActionPreference = $previous }
}

function Invoke-Analyze([string[]]$Extra) {
    $before = @(Get-ChildItem -LiteralPath $Output -Directory -Filter 'FetchNetworkAnalysis-*' | ForEach-Object FullName)
    $arguments = @('analyze', $Evidence, '--output', $Output)
    if ($LogUtcOffset) { $arguments += @('--log-utc-offset', $LogUtcOffset) }
    $arguments += $Extra
    Invoke-Native { & $Exe @arguments 2>&1 | Out-Host }
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) { throw "analyze failed with exit code $LASTEXITCODE." }
    $created = @(Get-ChildItem -LiteralPath $Output -Directory -Filter 'FetchNetworkAnalysis-*' |
        Where-Object { $before -notcontains $_.FullName } | Sort-Object CreationTimeUtc)
    if ($created.Count -eq 0) { throw 'analyze did not create a result folder.' }
    return $created[-1].FullName
}

if (-not $Exe) { $Exe = Find-Exe }
$Evidence = (Resolve-Path -LiteralPath $Evidence).Path
if (-not $Output) { $Output = Split-Path -Parent $Exe }
$Output = (Resolve-Path -LiteralPath $Output).Path

$codex = Get-Command codex -ErrorAction SilentlyContinue
if (-not $codex) { throw 'Codex CLI not found. Install it (npm install -g @openai/codex) and run "codex login" with your ChatGPT account.' }
Invoke-Native { & codex login status 2>&1 | Out-Null }
if ($LASTEXITCODE -ne 0) { throw 'Codex CLI is not signed in. Run "codex login" first.' }

Write-Host '[1/3] Rule-based analysis'
$first = Invoke-Analyze @()
$context = Join-Path $first 'llm-context.json'
$contextText = [IO.File]::ReadAllText($context, [Text.Encoding]::UTF8)

Write-Host ''
Write-Host "Context to send: $context ($([Math]::Round($contextText.Length / 1024)) KiB)"
Write-Host 'Masked: computer name, user profile names, camera serials, MAC lower 3 bytes, public IPv4. Private IPv4 subnets are kept.'
if (-not $Yes) {
    $answer = Read-Host 'Send this context to the LLM via Codex CLI? (y/N)'
    if ($answer -notmatch '^(y|yes)$') { Write-Host "Cancelled. The rule-based report is at $first\analysis.html"; exit 0 }
}

Write-Host '[2/3] Codex review'
$schema = Join-Path $PSScriptRoot 'ai-review.schema.json'
$review = Join-Path $first 'ai-review.json'
$prompt = @'
You are a senior machine-vision field engineer reviewing a GigE Vision camera PC.
The <context> block below is llm-context.json produced by an offline rule engine.

Rules:
- Use only the provided data. Do not invent values, logs or settings.
- diagnosis.findings are verified rule results (basis 확인 = observed, 추정 = inferred from timing/name match).
  Cite their "id" values in finding_ids. Only cite ids that exist in the context.
- Explain the most probable root cause chain for camera image loss, disconnects or crashes, ranked by confidence.
- Give an ordered action list a technician can perform on site (NIC settings, cabling, PoE, filters, firewall, SDK).
- List additional checks for anything marked "unknown" or not covered by the data.
- Correlation in time is not proof of causation; say so where relevant.
- Write all text in Korean. Set schema_version to 1, model to your model name or null, generated_at to null.
Do not run commands or read files; answer directly.
'@
$codexArgs = @('exec', '--skip-git-repo-check', '--ephemeral', '--sandbox', 'read-only', '-C', $first,
               '--output-schema', $schema, '-o', $review)
if ($Model) { $codexArgs += @('-m', $Model) }
$codexArgs += '-'  # Prompt and context are sent on stdin; multi-line arguments are unreliable through the npm shim.
$previousEncoding = $OutputEncoding
try {
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $stdin = $prompt + "`n<context>`n" + $contextText + "`n</context>`n"
    Invoke-Native { $stdin | & codex @codexArgs 2>&1 | Out-Null }
} finally { $OutputEncoding = $previousEncoding }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $review)) { throw "codex exec failed (exit $LASTEXITCODE)." }
$null = [IO.File]::ReadAllText($review, [Text.Encoding]::UTF8) | ConvertFrom-Json

Write-Host '[3/3] Final report with AI opinion'
$final = Invoke-Analyze @('--ai-review', $review)
Write-Host ''
Write-Host "AI review JSON : $review"
Write-Host "Final report   : $(Join-Path $final 'analysis.html')"
