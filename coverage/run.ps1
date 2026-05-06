#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs the IPBanTests test suite under coverlet and produces a raw + HTML coverage report.

.DESCRIPTION
    PowerShell port of coverage/run.sh. Invokes `dotnet test` with the XPlat Code Coverage
    collector against IPBanTests/IPBanTests.csproj, prints a summary derived from the
    cobertura XML, and (if reportgenerator is installed) renders an HTML report.

.PARAMETER Filter
    Optional NUnit / dotnet-test filter expression passed through to `dotnet test --filter`.
    Example: -Filter "Category!=LinuxIntegrationSlow".

.EXAMPLE
    .\coverage\run.ps1
    .\coverage\run.ps1 -Filter "FullyQualifiedName~IPBanFirewallTests"
#>
param(
    [string]$Filter = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$repoRoot  = Split-Path -Parent $scriptDir
Set-Location $repoRoot

# Install reportgenerator on demand
if (-not (Get-Command reportgenerator -ErrorAction SilentlyContinue)) {
    if (Get-Command dotnet -ErrorAction SilentlyContinue) {
        Write-Host ">> installing dotnet-reportgenerator-globaltool" -ForegroundColor Cyan
        try { dotnet tool install -g dotnet-reportgenerator-globaltool | Out-Null } catch { }
        $toolsDir = Join-Path $env:USERPROFILE ".dotnet\tools"
        if (Test-Path $toolsDir -and ($env:Path -notlike "*$toolsDir*")) {
            $env:Path = "$env:Path;$toolsDir"
        }
    }
}

$resultsDir = Join-Path $repoRoot "coverage/results"
$reportDir  = Join-Path $repoRoot "coverage/report"

# Wipe old results so we don't aggregate across runs
Remove-Item -Recurse -Force $resultsDir, $reportDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

Write-Host ">> running tests with coverage collection" -ForegroundColor Cyan
$testArgs = @(
    "IPBanTests/IPBanTests.csproj",
    "--collect:XPlat Code Coverage",
    "--settings", (Join-Path $scriptDir "coverlet.runsettings"),
    "--results-directory", $resultsDir,
    "-c", "Release",
    "--logger", "console;verbosity=minimal"
)
if ($Filter) { $testArgs += @("--filter", $Filter) }

dotnet test @testArgs

# Locate the cobertura xml the collector wrote
$cobertura = Get-ChildItem -Path $resultsDir -Recurse -Filter "coverage.cobertura.xml" |
             Select-Object -First 1 -ExpandProperty FullName
if (-not $cobertura) {
    Write-Error ">> no coverage.cobertura.xml produced — check that coverlet.collector is referenced in IPBanTests.csproj"
    exit 1
}
Write-Host ">> raw report: $cobertura" -ForegroundColor Green

# Print a summary using summary.py (matches run.sh output) — fall back to inline parse if python is missing
$summaryScript = Join-Path $scriptDir "summary.py"
$python = $null
foreach ($candidate in @("python3", "python", "py")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $python = $candidate; break }
}

if ($python -and (Test-Path $summaryScript)) {
    & $python $summaryScript $cobertura
} else {
    Write-Host ""
    Write-Host "=== Coverage summary ===" -ForegroundColor Yellow
    [xml]$xml = Get-Content $cobertura
    $lineRate   = [double]$xml.coverage.'line-rate'   * 100
    $branchRate = [double]$xml.coverage.'branch-rate' * 100
    "  line   coverage: {0,6:N2}%" -f $lineRate
    "  branch coverage: {0,6:N2}%" -f $branchRate
}

# Render HTML if reportgenerator is available
if (Get-Command reportgenerator -ErrorAction SilentlyContinue) {
    Write-Host ">> generating HTML report at coverage/report/index.html" -ForegroundColor Cyan
    reportgenerator `
        -reports:"$cobertura" `
        -targetdir:"$reportDir" `
        -reporttypes:"Html;Badges;TextSummary" | Out-Null
    Write-Host ">> open coverage/report/index.html in a browser" -ForegroundColor Green
} else {
    Write-Host ">> reportgenerator not on PATH — skipped HTML render" -ForegroundColor Yellow
}
