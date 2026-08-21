$ErrorActionPreference = "Continue"

# ============================================================

# ZeroPhish Security Gate

# ============================================================

# Safe verification script.

# Does NOT commit, push, rotate credentials, or rewrite history.

# Run from any directory:

# .\security-gate.ps1

# ============================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot  = Split-Path -Parent $ScriptDir

$BackendDir   = Join-Path $RepoRoot "Backend"
$FrontendDir  = Join-Path $RepoRoot "Frontend"
$ExtensionDir = Join-Path $RepoRoot "Extension"

$PassCount = 0
$WarnCount = 0
$FailCount = 0

$Results = @()

function Section {
param([string]$Name)

Write-Host ""
Write-Host ("=" * 78) -ForegroundColor DarkGray
Write-Host $Name -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor DarkGray

}

function Pass {
param(
[string]$Name,
[string]$Details = ""
)

$script:PassCount++

$script:Results += [PSCustomObject]@{
    Status  = "PASS"
    Check   = $Name
    Details = $Details
}

Write-Host "[PASS] $Name" -ForegroundColor Green

if ($Details) {
    Write-Host "       $Details" -ForegroundColor DarkGray
}

}

function Warn {
param(
[string]$Name,
[string]$Details = ""
)

$script:WarnCount++

$script:Results += [PSCustomObject]@{
    Status  = "WARN"
    Check   = $Name
    Details = $Details
}

Write-Host "[WARN] $Name" -ForegroundColor Yellow

if ($Details) {
    Write-Host "       $Details" -ForegroundColor DarkGray
}

}

function Fail {
param(
[string]$Name,
[string]$Details = ""
)

$script:FailCount++

$script:Results += [PSCustomObject]@{
    Status  = "FAIL"
    Check   = $Name
    Details = $Details
}

Write-Host "[FAIL] $Name" -ForegroundColor Red

if ($Details) {
    Write-Host "       $Details" -ForegroundColor DarkGray
}

}

function Has-Command {
param([string]$Name)

return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)

}

# ============================================================

# 1. Repository sanity

# ============================================================

Section "1. REPOSITORY SANITY"

Set-Location $RepoRoot

Write-Host "Repository root:" -ForegroundColor White
Write-Host "  $RepoRoot" -ForegroundColor DarkGray

if (Test-Path (Join-Path $RepoRoot ".git")) {
Pass "Git repository detected"
}
else {
Fail "Git repository" "No .git directory found."
exit 1
}

if (Test-Path $BackendDir) {
Pass "Backend directory detected"
}
else {
Warn "Backend directory" "Backend/ not found."
}

if (Test-Path (Join-Path $FrontendDir "package.json")) {
Pass "Frontend package.json detected"
}
else {
Warn "Frontend package.json" "Frontend/package.json not found."
}

if (Test-Path (Join-Path $ExtensionDir "manifest.json")) {
Pass "Chrome extension detected"
}
else {
Warn "Chrome extension" "Extension/manifest.json not found."
}

# ============================================================

# 2. Git state

# ============================================================

Section "2. GIT STATE"

$Branch = git branch --show-current 2>$null

if ($LASTEXITCODE -eq 0) {
Pass "Current branch" $Branch
}

$Remote = git remote get-url origin 2>$null

if ($LASTEXITCODE -eq 0 -and $Remote) {
Pass "Origin remote configured"
}
else {
Warn "Origin remote" "No origin remote detected."
}

$GitStatus = git status --short 2>$null

if ($GitStatus) {
Warn "Working tree has changes" "Expected during remediation."
Write-Host ""
Write-Host $GitStatus -ForegroundColor DarkGray
}
else {
Pass "Working tree clean"
}

# ============================================================

# 3. Toolchain

# ============================================================

Section "3. TOOLCHAIN"

if (Has-Command "git") {
Pass "Git" ((git --version) -join " ")
}
else {
Fail "Git" "Git not available."
}

if (Has-Command "python") {
Pass "Python" ((python --version) -join " ")
}
else {
Warn "Python" "Python not available."
}

if (Has-Command "node") {
Pass "Node.js" ((node --version) -join " ")
}
else {
Warn "Node.js" "Node not available."
}

if (Has-Command "npm") {
Pass "npm" ((npm --version) -join " ")
}
else {
Warn "npm" "npm not available."
}

if (Has-Command "pnpm") {
Pass "pnpm" ((pnpm --version) -join " ")
}
else {
Warn "pnpm" "pnpm not available."
}

if (Has-Command "gitleaks") {
Pass "Gitleaks" ((gitleaks version) -join " ")
}
else {
Warn "Gitleaks" "Not available in this PowerShell PATH. Restart PowerShell after installation."
}

# ============================================================

# 4. Secret verification

# ============================================================

Section "4. SECRET VERIFICATION"

Write-Host "Checking whether Backend/.env exists in Git history..." -ForegroundColor White

$EnvHistory = git log --all --full-history -- "Backend/.env" 2>$null

if ($EnvHistory) {
Fail "Backend/.env Git history" "Backend/.env exists in Git history."
}
else {
Pass "Backend/.env Git history" "No Git history entries found."
}

if (Has-Command "gitleaks") {

Write-Host ""
Write-Host "Running Gitleaks Git scan..." -ForegroundColor White

gitleaks git --verbose

if ($LASTEXITCODE -eq 0) {
    Pass "Gitleaks Git scan"
}
else {
    Fail "Gitleaks Git scan" "Potential secret findings detected."
}

Write-Host ""
Write-Host "Running Gitleaks working-tree scan..." -ForegroundColor White

gitleaks detect --source $RepoRoot --verbose

if ($LASTEXITCODE -eq 0) {
    Pass "Gitleaks working-tree scan"
}
else {
    Fail "Gitleaks working-tree scan" "Potential secret findings detected."
}

}
else {
Warn "Gitleaks scans skipped" "Gitleaks not available."
}

# ============================================================

# 5. Environment files

# ============================================================

Section "5. ENVIRONMENT FILE SECURITY"

$EnvPath = Join-Path $BackendDir ".env"
$EnvExamplePath = Join-Path $BackendDir ".env.example"

if (Test-Path $EnvPath) {

Pass "Backend/.env exists locally"

$TrackedEnv = git ls-files -- "Backend/.env" 2>$null

if ($TrackedEnv) {
    Fail "Backend/.env tracking" "Backend/.env is tracked by Git."
}
else {
    Pass "Backend/.env not tracked"
}

}
else {
Warn "Backend/.env" "No local Backend/.env file found."
}

if (Test-Path $EnvExamplePath) {

Pass "Backend/.env.example exists"

$Example = Get-Content $EnvExamplePath -Raw

$DangerPatterns = @(
    "AIza[0-9A-Za-z_-]+",
    "ghp_[0-9A-Za-z]+",
    "github_pat_[0-9A-Za-z_]+",
    "sk-[0-9A-Za-z]+"
)

$FoundDanger = $false

foreach ($Pattern in $DangerPatterns) {

    if ($Example -match $Pattern) {
        $FoundDanger = $true
    }
}

if ($FoundDanger) {
    Warn ".env.example secret hygiene" "Potential credential-like value detected."
}
else {
    Pass ".env.example secret hygiene"
}

}
else {
Warn "Backend/.env.example" "Missing."
}

# ============================================================

# 6. Gitignore

# ============================================================

Section "6. GITIGNORE"

$GitignorePath = Join-Path $RepoRoot ".gitignore"

if (Test-Path $GitignorePath) {

$GitignoreText = Get-Content $GitignorePath -Raw

if ($GitignoreText -match "(?m)^\s*\.env\s*$" -or
    $GitignoreText -match "(?m)^\s*\.env\.\*\s*$") {

    Pass ".env ignore rule"

}
else {
    Warn ".env ignore rule" "No obvious .env ignore rule found."
}

}
else {
Warn ".gitignore" "Root .gitignore not found."
}

# ============================================================

# 7. Repository security controls

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
    Pass $File
}
else {
    Warn $File "File missing."
}

}

# ============================================================

# 8. Backend tests

# ============================================================

Section "8. BACKEND TESTS"

if (Test-Path $BackendDir) {

if (Has-Command "python") {

    Push-Location $BackendDir

    python -m pytest tests/ -v

    $TestExit = $LASTEXITCODE

    Pop-Location

    if ($TestExit -eq 0) {
        Pass "Backend pytest suite"
    }
    else {
        Fail "Backend pytest suite" "pytest exited with code $TestExit."
    }

}
else {
    Warn "Backend tests" "Python unavailable."
}

}
else {
Warn "Backend tests" "Backend directory unavailable."
}

# ============================================================

# 9. Backend coverage

# ============================================================

Section "9. BACKEND COVERAGE"

if (Test-Path $BackendDir) {

if (Has-Command "python") {

    Push-Location $BackendDir

    python -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=xml

    $CoverageExit = $LASTEXITCODE

    Pop-Location

    if ($CoverageExit -eq 0) {
        Pass "Backend coverage"
    }
    else {
        Warn "Backend coverage" "Coverage command exited with code $CoverageExit."
    }

}
else {
    Warn "Backend coverage" "Python unavailable."
}

}

# ============================================================

# 10. pip-audit

# ============================================================

Section "10. PYTHON DEPENDENCY SECURITY"

if (Has-Command "python") {

python -m pip_audit --version *> $null

if ($LASTEXITCODE -eq 0) {

    Push-Location $BackendDir

    python -m pip_audit

    $AuditExit = $LASTEXITCODE

    Pop-Location

    if ($AuditExit -eq 0) {
        Pass "pip-audit"
    }
    else {
        Fail "pip-audit" "Potential dependency vulnerabilities detected."
    }

}
else {
    Warn "pip-audit" "Not installed."
}

}

# ============================================================

# 11. Frontend

# ============================================================

Section "11. FRONTEND BUILD"

if (Test-Path (Join-Path $FrontendDir "package.json")) {

Push-Location $FrontendDir

if (Has-Command "pnpm") {

    Write-Host "Running pnpm install --frozen-lockfile..." -ForegroundColor White

    pnpm install --frozen-lockfile

    if ($LASTEXITCODE -ne 0) {

        Fail "Frontend dependency install" "pnpm install failed."

    }
    else {

        Pass "Frontend dependency install"

        Write-Host ""
        Write-Host "Running production build..." -ForegroundColor White

        pnpm build

        if ($LASTEXITCODE -eq 0) {
            Pass "Frontend production build"
        }
        else {
            Fail "Frontend production build"
        }

        Write-Host ""
        Write-Host "Running npm audit..." -ForegroundColor White

        npm audit --audit-level=high

        if ($LASTEXITCODE -eq 0) {
            Pass "npm audit"
        }
        else {
            Warn "npm audit" "High/critical dependency findings may exist."
        }
    }

}
elseif (Has-Command "npm") {

    Write-Host "pnpm unavailable; using npm." -ForegroundColor Yellow

    npm install

    if ($LASTEXITCODE -ne 0) {
        Fail "Frontend dependency install" "npm install failed."
    }
    else {

        npm run build

        if ($LASTEXITCODE -eq 0) {
            Pass "Frontend production build"
        }
        else {
            Fail "Frontend production build"
        }

        npm audit --audit-level=high

        if ($LASTEXITCODE -eq 0) {
            Pass "npm audit"
        }
        else {
            Warn "npm audit" "Potential dependency findings."
        }
    }

}
else {
    Warn "Frontend build" "Neither pnpm nor npm available."
}

Pop-Location

}
else {
Warn "Frontend build" "Frontend/package.json not found."
}

# ============================================================

# 12. Chrome extension validation

# ============================================================

Section "12. EXTENSION VALIDATION"

$ManifestPath = Join-Path $ExtensionDir "manifest.json"

if (Test-Path $ManifestPath) {

try {

    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json

    if ($Manifest.manifest_version -eq 3) {
        Pass "Manifest V3"
    }
    else {
        Fail "Manifest V3" "manifest_version is not 3."
    }

    $Permissions = @($Manifest.permissions)

    Write-Host "Permissions:" -ForegroundColor White

    foreach ($Permission in $Permissions) {
        Write-Host "  - $Permission" -ForegroundColor DarkGray
    }

    Pass "Extension manifest parsed"

}
catch {

    Fail "Extension manifest" "manifest.json could not be parsed."

}

}
else {
Warn "Extension manifest" "Extension/manifest.json not found."
}

# ============================================================

# 13. Static analysis

# ============================================================

Section "13. STATIC SECURITY ANALYSIS"

if (Has-Command "semgrep") {

semgrep scan --config auto --error

if ($LASTEXITCODE -eq 0) {
    Pass "Semgrep"
}
else {
    Fail "Semgrep" "Semgrep reported findings."
}

}
else {
Warn "Semgrep" "Not installed."
}

# ============================================================

# 14. Final Git state

# ============================================================

Section "14. FINAL GIT STATE"

Set-Location $RepoRoot

git status --short

# ============================================================

# Final result

# ============================================================

Section "SECURITY GATE RESULT"

Write-Host ""
Write-Host "PASS : $PassCount" -ForegroundColor Green
Write-Host "WARN : $WarnCount" -ForegroundColor Yellow
Write-Host "FAIL : $FailCount" -ForegroundColor Red
Write-Host ""

if ($FailCount -eq 0) {

Write-Host "SECURITY GATE: PASSED" -ForegroundColor Green
Write-Host "Review WARN items before production." -ForegroundColor Yellow

}
else {

Write-Host "SECURITY GATE: FAILED" -ForegroundColor Red
Write-Host "Resolve FAIL items before treating ZeroPhish as production-ready." -ForegroundColor Red

}

Write-Host ""
Write-Host "Detailed results:" -ForegroundColor Cyan

$Results | Format-Table -AutoSize

if ($FailCount -gt 0) {
exit 1
}

exit 0
