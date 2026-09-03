<#
.SYNOPSIS
    ZeroPhish Security Gate – safe verification script.

.DESCRIPTION
    This script runs a comprehensive suite of security, quality, and dependency
    checks on the ZeroPhish repository. It does NOT commit, push, rotate credentials,
    or rewrite history.

    It can be run from any directory and will locate the repository root.

.PARAMETER SkipBackendTests
    Skip running pytest and coverage for the backend.

.PARAMETER SkipFrontend
    Skip frontend dependency install, build, and audit.

.PARAMETER SkipGitleaks
    Skip Gitleaks scans (Git history and working tree).

.PARAMETER SkipManual
    Skip manual action reminders.

.PARAMETER SkipSemgrep
    Skip Semgrep static analysis.

.PARAMETER SkipPipAudit
    Skip pip-audit for Python dependencies.

.PARAMETER LogFile
    Path to a log file where the full output will be written.

.PARAMETER Verbose
    Enable verbose output.

.EXAMPLE
    .\security-gate.ps1 -Verbose
    .\security-gate.ps1 -SkipBackendTests -SkipFrontend
    .\security-gate.ps1 -LogFile .\security-gate.log
#>

[CmdletBinding()]
param(
    [switch]$SkipBackendTests,
    [switch]$SkipFrontend,
    [switch]$SkipGitleaks,
    [switch]$SkipManual,
    [switch]$SkipSemgrep,
    [switch]$SkipPipAudit,
    [string]$LogFile,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"

# ---------- Helper Functions ----------
function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Write-Debug {
    param([string]$Message)
    if ($Verbose) { Write-Host "🔍 $Message" -ForegroundColor DarkGray }
}

function Section {
    param([string]$Name)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host $Name -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Has-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Check-Result {
    param(
        [string]$Name,
        [bool]$Pass,
        [string]$Details = "",
        [string]$Status = "PASS"
    )
    $script:Results += [PSCustomObject]@{
        Status  = if ($Pass) { $Status } else { "FAIL" }
        Check   = $Name
        Details = $Details
    }
    if ($Pass) {
        $script:PassCount++
        Write-Success "$Name"
        if ($Details) { Write-Host "       $Details" -ForegroundColor DarkGray }
    } else {
        $script:FailCount++
        Write-Error "$Name"
        if ($Details) { Write-Host "       $Details" -ForegroundColor DarkGray }
    }
}

function Check-Warn {
    param([string]$Name, [string]$Details = "")
    $script:WarnCount++
    $script:Results += [PSCustomObject]@{
        Status  = "WARN"
        Check   = $Name
        Details = $Details
    }
    Write-Warning "$Name"
    if ($Details) { Write-Host "       $Details" -ForegroundColor DarkGray }
}

function Check-Skipped {
    param([string]$Name, [string]$Details = "")
    $script:SkipCount++
    $script:Results += [PSCustomObject]@{
        Status  = "SKIPPED"
        Check   = $Name
        Details = $Details
    }
    Write-Host "[SKIPPED] $Name" -ForegroundColor DarkGray
    if ($Details) { Write-Host "          $Details" -ForegroundColor DarkGray }
}

function Check-Manual {
    param([string]$Name, [string]$Details = "")
    $script:ManualCount++
    $script:Results += [PSCustomObject]@{
        Status  = "MANUAL"
        Check   = $Name
        Details = $Details
    }
    Write-Host "[MANUAL] $Name" -ForegroundColor Magenta
    if ($Details) { Write-Host "         $Details" -ForegroundColor DarkGray }
}

# ---------- Script Initialisation ----------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir

# Ensure WinGet / Link paths are in PATH for current session
$WingetLinks = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links"
if (Test-Path $WingetLinks) {
    if ($env:PATH -notlike "*$WingetLinks*") {
        $env:PATH = "$WingetLinks;$env:PATH"
    }
}

# Set up logging
if ($LogFile) {
    $LogFile = Resolve-Path -Path $LogFile -ErrorAction SilentlyContinue
    if (-not $LogFile) {
        $LogFile = Join-Path $RepoRoot "security-gate.log"
    }
    Start-Transcript -Path $LogFile -Append
    Write-Info "Logging to $LogFile"
}

# Global counters
$PassCount = 0
$WarnCount = 0
$FailCount = 0
$ManualCount = 0
$SkipCount = 0
$Results = @()

# Determine directories
$BackendDir = Join-Path $RepoRoot "Backend"
$FrontendDir = Join-Path $RepoRoot "Frontend"
$ExtensionDir = if (Test-Path (Join-Path $RepoRoot "extension")) {
    Join-Path $RepoRoot "extension"
} else {
    Join-Path $RepoRoot "Extension"
}

# ============================================================
# 1. REPOSITORY SANITY
# ============================================================
Section "1. REPOSITORY SANITY"

Set-Location $RepoRoot
Write-Debug "Repository root: $RepoRoot"

$checks = @(
    @{ Name = "Git repository"; Test = { Test-Path (Join-Path $RepoRoot ".git") } },
    @{ Name = "Backend directory"; Test = { Test-Path $BackendDir } },
    @{ Name = "Frontend package.json"; Test = { Test-Path (Join-Path $FrontendDir "package.json") } },
    @{ Name = "Chrome extension manifest"; Test = { Test-Path (Join-Path $ExtensionDir "manifest.json") } }
)

foreach ($c in $checks) {
    $pass = & $c.Test
    Check-Result -Name $c.Name -Pass $pass -Details (if ($pass) { "Found" } else { "Missing" })
}

# ============================================================
# 2. GIT STATE
# ============================================================
Section "2. GIT STATE"

$Branch = git branch --show-current 2>$null
if ($LASTEXITCODE -eq 0 -and $Branch) {
    Check-Result -Name "Current branch" -Pass $true -Details $Branch
} else {
    Check-Warn "Current branch" "Could not determine branch."
}

$Remote = git remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0 -and $Remote) {
    Check-Result -Name "Origin remote" -Pass $true -Details $Remote
} else {
    Check-Skipped "Origin remote" "Not configured."
}

$GitStatus = git status --short 2>$null
if ($GitStatus) {
    Check-Result -Name "Working tree inspected" -Pass $true -Details "Changes present (review them)."
} else {
    Check-Result -Name "Working tree clean" -Pass $true
}

# ============================================================
# 3. TOOLCHAIN
# ============================================================
Section "3. TOOLCHAIN"

$tools = @(
    @{ Name = "Git"; Cmd = "git"; VersionArg = "--version" },
    @{ Name = "Python"; Cmd = "python"; VersionArg = "--version" },
    @{ Name = "Node.js"; Cmd = "node"; VersionArg = "--version" },
    @{ Name = "pnpm"; Cmd = "pnpm"; VersionArg = "--version" },
    @{ Name = "Gitleaks"; Cmd = "gitleaks"; VersionArg = "version" }
)

foreach ($t in $tools) {
    if (Has-Command $t.Cmd) {
        $ver = & $t.Cmd $t.VersionArg 2>&1 | Out-String
        Check-Result -Name $t.Name -Pass $true -Details ($ver -replace "`n", " ").Trim()
    } else {
        Check-Skipped $t.Name "Not found in PATH."
    }
}

# ============================================================
# 4. SECRET VERIFICATION (Gitleaks)
# ============================================================
Section "4. SECRET VERIFICATION"

# Check if Backend/.env exists in Git history
$EnvHistory = git log --all --full-history -- "Backend/.env" 2>$null
if ($EnvHistory) {
    Check-Result -Name "Backend/.env Git history" -Pass $false -Details "Found in Git history."
} else {
    Check-Result -Name "Backend/.env Git history" -Pass $true -Details "No history entries."
}

if (-not $SkipGitleaks) {
    if (Has-Command "gitleaks") {
        $ignorePath = Join-Path $RepoRoot ".gitleaksignore"
        $ignoreArg = if (Test-Path $ignorePath) { @("--gitleaks-ignore-path", $ignorePath) } else { @() }

        Write-Info "Running Gitleaks Git scan..."
        $gitleaksGit = gitleaks git --verbose @ignoreArg 2>&1
        if ($LASTEXITCODE -eq 0 -or ($gitleaksGit -match "no leaks found")) {
            Check-Result -Name "Gitleaks Git scan" -Pass $true -Details "No leaks detected."
        } else {
            Check-Result -Name "Gitleaks Git scan" -Pass $false -Details "Findings detected."
        }

        Write-Info "Running Gitleaks working-tree scan..."
        $gitleaksDetect = gitleaks detect --source $RepoRoot --verbose @ignoreArg 2>&1
        if ($LASTEXITCODE -eq 0 -or ($gitleaksDetect -match "no leaks found")) {
            Check-Result -Name "Gitleaks working-tree scan" -Pass $true -Details "No leaks detected."
        } else {
            Check-Result -Name "Gitleaks working-tree scan" -Pass $false -Details "Findings detected."
        }
    } else {
        Check-Skipped "Gitleaks scans" "Gitleaks not available."
    }
} else {
    Check-Skipped "Gitleaks scans" "Skipped by user."
}

# ============================================================
# 5. ENVIRONMENT FILE SECURITY
# ============================================================
Section "5. ENVIRONMENT FILE SECURITY"

$EnvPath = Join-Path $BackendDir ".env"
$EnvExamplePath = Join-Path $BackendDir ".env.example"

if (Test-Path $EnvPath) {
    $Tracked = git ls-files -- "Backend/.env" 2>$null
    if ($Tracked) {
        Check-Result -Name "Backend/.env tracking" -Pass $false -Details "Tracked by Git."
    } else {
        Check-Result -Name "Backend/.env tracking" -Pass $true -Details "Untracked (OK)."
    }
} else {
    Check-Result -Name "Backend/.env exists" -Pass $true -Details "Not present (OK)."
}

if (Test-Path $EnvExamplePath) {
    $Example = Get-Content $EnvExamplePath -Raw
    $DangerPatterns = @(
        "AIza[0-9A-Za-z_-]{30,}",
        "ghp_[0-9A-Za-z]{30,}",
        "github_pat_[0-9A-Za-z_]{30,}",
        "sk-[0-9A-Za-z]{30,}"
    )
    $FoundDanger = $false
    foreach ($Pattern in $DangerPatterns) {
        if ($Example -match $Pattern) { $FoundDanger = $true; break }
    }
    if ($FoundDanger) {
        Check-Result -Name ".env.example secret hygiene" -Pass $false -Details "Potential credential-like value detected."
    } else {
        Check-Result -Name ".env.example secret hygiene" -Pass $true -Details "All values are placeholders."
    }
} else {
    Check-Result -Name "Backend/.env.example" -Pass $false -Details "Missing."
}

# ============================================================
# 6. GITIGNORE
# ============================================================
Section "6. GITIGNORE"

$GitignorePath = Join-Path $RepoRoot ".gitignore"
if (Test-Path $GitignorePath) {
    $GitignoreText = Get-Content $GitignorePath -Raw
    if ($GitignoreText -match "(?m)^\s*\.env\s*$" -or $GitignoreText -match "(?m)^\s*\.env\.\*\s*$") {
        Check-Result -Name ".env ignore rule" -Pass $true
    } else {
        Check-Result -Name ".env ignore rule" -Pass $false -Details "No obvious .env ignore rule found."
    }
} else {
    Check-Result -Name ".gitignore" -Pass $false -Details "Root .gitignore not found."
}

# ============================================================
# 7. REPOSITORY SECURITY CONTROLS
# ============================================================
Section "7. REPOSITORY SECURITY CONTROLS"

$SecurityFiles = @(
    ".github\dependabot.yml",
    ".github\workflows\codeql.yml",
    "CODEOWNERS",
    "SECURITY.md"
)

foreach ($File in $SecurityFiles) {
    $Path = Join-Path $RepoRoot $File
    if (Test-Path $Path) {
        Check-Result -Name $File -Pass $true
    } else {
        Check-Result -Name $File -Pass $false -Details "Missing."
    }
}

# ============================================================
# 8. BACKEND TESTS
# ============================================================
Section "8. BACKEND TESTS"

if (-not $SkipBackendTests) {
    if (Test-Path $BackendDir -and (Has-Command "python")) {
        Push-Location $BackendDir
        Write-Info "Running pytest..."
        python -m pytest tests/ -v --tb=short
        $TestExit = $LASTEXITCODE
        Pop-Location
        if ($TestExit -eq 0) {
            Check-Result -Name "Backend pytest suite" -Pass $true -Details "All tests passing."
        } else {
            Check-Result -Name "Backend pytest suite" -Pass $false -Details "pytest exited with code $TestExit."
        }
    } else {
        Check-Skipped "Backend tests" "Python or Backend directory missing."
    }
} else {
    Check-Skipped "Backend tests" "Skipped by user."
}

# ============================================================
# 9. BACKEND COVERAGE
# ============================================================
Section "9. BACKEND COVERAGE"

if (-not $SkipBackendTests) {
    if (Test-Path $BackendDir -and (Has-Command "python")) {
        Push-Location $BackendDir
        Write-Info "Running coverage report..."
        python -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=xml
        $CoverageExit = $LASTEXITCODE
        Pop-Location
        if ($CoverageExit -eq 0) {
            Check-Result -Name "Backend coverage" -Pass $true -Details "Coverage report generated."
        } else {
            Check-Result -Name "Backend coverage" -Pass $false -Details "Coverage command exited with code $CoverageExit."
        }
    } else {
        Check-Skipped "Backend coverage" "Python or Backend directory missing."
    }
} else {
    Check-Skipped "Backend coverage" "Skipped by user."
}

# ============================================================
# 10. pip-audit
# ============================================================
Section "10. PYTHON DEPENDENCY SECURITY"

if (-not $SkipPipAudit) {
    if (Has-Command "python") {
        $pipAuditInstalled = python -c "import pip_audit" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Push-Location $BackendDir
            Write-Info "Running pip-audit..."
            $auditOut = python -m pip_audit -r requirements.txt 2>&1
            $AuditExit = $LASTEXITCODE
            Pop-Location
            if ($AuditExit -eq 0) {
                Check-Result -Name "pip-audit" -Pass $true -Details "0 vulnerabilities detected."
            } else {
                Check-Warn "pip-audit" "Vulnerabilities found – see SECURITY.md for exceptions."
            }
        } else {
            Check-Skipped "pip-audit" "pip-audit not installed."
        }
    } else {
        Check-Skipped "pip-audit" "Python not available."
    }
} else {
    Check-Skipped "pip-audit" "Skipped by user."
}

# ============================================================
# 11. FRONTEND
# ============================================================
Section "11. FRONTEND BUILD & AUDIT"

if (-not $SkipFrontend) {
    if (Test-Path (Join-Path $FrontendDir "package.json")) {
        Push-Location $FrontendDir
        if (Has-Command "pnpm") {
            Write-Info "Running pnpm install --frozen-lockfile..."
            pnpm install --frozen-lockfile
            if ($LASTEXITCODE -eq 0) {
                Check-Result -Name "Frontend dependency install" -Pass $true
                Write-Info "Running production build..."
                pnpm build
                if ($LASTEXITCODE -eq 0) {
                    Check-Result -Name "Frontend production build" -Pass $true
                } else {
                    Check-Result -Name "Frontend production build" -Pass $false
                }
                Write-Info "Running pnpm audit..."
                pnpm audit --audit-level=high
                if ($LASTEXITCODE -eq 0) {
                    Check-Result -Name "pnpm audit" -Pass $true -Details "0 high/critical vulnerabilities."
                } else {
                    Check-Result -Name "pnpm audit" -Pass $false -Details "High/critical vulnerabilities found."
                }
            } else {
                Check-Result -Name "Frontend dependency install" -Pass $false
            }
        } else {
            Check-Skipped "Frontend" "pnpm not available."
        }
        Pop-Location
    } else {
        Check-Result -Name "Frontend" -Pass $false -Details "Frontend/package.json not found."
    }
} else {
    Check-Skipped "Frontend" "Skipped by user."
}

# ============================================================
# 12. CHROME EXTENSION VALIDATION
# ============================================================
Section "12. EXTENSION VALIDATION"

$ManifestPath = Join-Path $ExtensionDir "manifest.json"
if (Test-Path $ManifestPath) {
    try {
        $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
        if ($Manifest.manifest_version -eq 3) {
            Check-Result -Name "Manifest V3" -Pass $true
        } else {
            Check-Result -Name "Manifest V3" -Pass $false -Details "manifest_version is $($Manifest.manifest_version)."
        }
        Write-Debug "Extension permissions: $($Manifest.permissions -join ', ')"
        Check-Result -Name "Extension manifest parsed" -Pass $true
    } catch {
        Check-Result -Name "Extension manifest" -Pass $false -Details "Could not parse JSON."
    }
} else {
    Check-Result -Name "Extension manifest" -Pass $false -Details "Missing."
}

# ============================================================
# 13. STATIC ANALYSIS (Semgrep)
# ============================================================
Section "13. STATIC SECURITY ANALYSIS"

if (-not $SkipSemgrep) {
    if (Has-Command "semgrep") {
        Write-Info "Running Semgrep..."
        semgrep scan --config auto --error
        if ($LASTEXITCODE -eq 0) {
            Check-Result -Name "Semgrep" -Pass $true
        } else {
            Check-Result -Name "Semgrep" -Pass $false -Details "Semgrep reported findings."
        }
    } else {
        Check-Skipped "Semgrep" "Not installed locally."
    }
} else {
    Check-Skipped "Semgrep" "Skipped by user."
}

# ============================================================
# 14. MANUAL / EXTERNAL CONTROLS
# ============================================================
Section "14. MANUAL & EXTERNAL CONTROLS"

if (-not $SkipManual) {
    Check-Manual "Gemini API Key Rotation" "Revoke/rotate historical development credentials in Google AI Studio."
    Check-Manual "GitHub Branch Protection" "Enforce pull request reviews & required status checks on main."
    Check-Manual "GitHub Secret Scanning" "Enable Secret Scanning and Push Protection via GitHub UI."
    Check-Manual "Docker Image Scan" "Run Trivy or similar on final staging/production images before release."
} else {
    Check-Skipped "Manual actions" "Skipped by user."
}

# ============================================================
# FINAL RESULT
# ============================================================
Section "SECURITY GATE RESULT"

Write-Host ""
Write-Host "PASS    : $PassCount" -ForegroundColor Green
Write-Host "WARN    : $WarnCount" -ForegroundColor Yellow
Write-Host "MANUAL  : $ManualCount" -ForegroundColor Magenta
Write-Host "SKIPPED : $SkipCount" -ForegroundColor DarkGray
Write-Host "FAIL    : $FailCount" -ForegroundColor Red
Write-Host ""

if ($FailCount -eq 0 -and $WarnCount -eq 0) {
    Write-Success "SECURITY GATE: PASSED (0 FAIL, 0 WARN)"
    Write-Info "All mandatory automated gates passed. Complete manual actions before live production release."
} else {
    Write-Error "SECURITY GATE: FAILED"
    Write-Error "Resolve FAIL/WARN items before treating ZeroPhish as release-ready."
}

Write-Host ""
Write-Host "Detailed results:" -ForegroundColor Cyan
$Results | Format-Table -AutoSize

if ($LogFile) {
    Stop-Transcript
    Write-Info "Full log saved to $LogFile"
}

if ($FailCount -gt 0) {
    exit 1
}
exit 0