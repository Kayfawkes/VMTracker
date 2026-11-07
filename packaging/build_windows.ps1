<#
.SYNOPSIS
    Builds VMTracker.exe (and optionally the installer) on Windows.

.DESCRIPTION
    Everything happens in a throwaway virtual environment under build\.venv, so
    nothing is installed into your system Python and repeat builds are clean.

    Steps: locate Python -> create venv -> install dependencies -> run tests ->
    build the executable -> smoke-test the built exe -> build the installer.

.PARAMETER OneFile
    Produce a single VMTracker.exe instead of a folder. Convenient to copy
    around, but it unpacks to a temp folder on every start, so it launches
    noticeably slower. The folder build is the better choice for a server.

.PARAMETER SkipTests
    Skip the test suite. Faster, but you lose the signal that the build is sound.

.PARAMETER Installer
    Also build the Inno Setup installer. Needs Inno Setup 6; the script looks in
    the usual install locations as well as on PATH.

.PARAMETER NoSmokeTest
    Skip launching the built exe to verify it serves the console.

.PARAMETER Python
    Path to a specific python.exe. Default: the newest 3.11+ the script can find.

.PARAMETER Clean
    Delete build\, dist\, packaging\Output\ and the venv before starting.

.EXAMPLE
    .\packaging\build_windows.ps1
    Folder build with tests and a smoke test.

.EXAMPLE
    .\packaging\build_windows.ps1 -OneFile -Installer
    Single-file exe plus the installer.
#>
[CmdletBinding()]
param(
    [switch]$OneFile,
    [switch]$SkipTests,
    [switch]$Installer,
    [switch]$NoSmokeTest,
    [string]$Python,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # stops Write-Progress slowing pip

$Root      = Split-Path -Parent $PSScriptRoot
$VenvDir   = Join-Path $Root 'build\.venv'
$DistDir   = Join-Path $Root 'dist'
$BuildDir  = Join-Path $Root 'build'
$OutputDir = Join-Path $Root 'packaging\Output'
$SmokePort = 9791          # not 9797: never collide with a running instance
$started   = Get-Date

# ---------------------------------------------------------------- output
function Step($n, $total, $msg) {
    Write-Host ''
    Write-Host "[$n/$total] $msg" -ForegroundColor Cyan
}
function Ok   ($msg) { Write-Host "      $msg" -ForegroundColor Green }
function Info ($msg) { Write-Host "      $msg" -ForegroundColor DarkGray }
function Warn ($msg) { Write-Host "      $msg" -ForegroundColor Yellow }
function Die  ($msg, $hint) {
    Write-Host ''
    Write-Host "BUILD FAILED" -ForegroundColor Red
    Write-Host "  $msg" -ForegroundColor Red
    if ($hint) { Write-Host "  $hint" -ForegroundColor Yellow }
    exit 1
}

# $IsWindows exists only in PowerShell 6+; on 5.1 the host is Windows by definition.
$onWindows = if ($null -eq $IsWindows) { $true } else { $IsWindows }
if (-not $onWindows) {
    Die "This script builds a Windows .exe and must run on Windows." `
        "On macOS or Linux use packaging/build_unix.sh, or let the GitHub Actions workflow build it."
}

Write-Host ''
Write-Host '  VM TRACKER - Windows build' -ForegroundColor White
Write-Host "  $Root" -ForegroundColor DarkGray

$total = 6
if ($Installer) { $total = 7 }

# ---------------------------------------------------------------- 0. clean
if ($Clean) {
    Write-Host ''
    Write-Host '[0] Cleaning previous build output' -ForegroundColor Cyan
    foreach ($d in @($BuildDir, $DistDir, $OutputDir)) {
        if (Test-Path $d) { Remove-Item $d -Recurse -Force; Info "removed $d" }
    }
}

# ---------------------------------------------------------------- 1. python
Step 1 $total 'Locating Python'

function Test-PythonCandidate {
    param([string]$Exe, [string[]]$PreArgs = @())
    try {
        $probe = $PreArgs + @('-c', "import sys; print('%d.%d|%s' % (sys.version_info[0], sys.version_info[1], sys.executable))")
        $out = & $Exe @probe 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $bits  = ($out | Select-Object -Last 1).Trim().Split('|')
        $parts = $bits[0].Split('.')
        return [pscustomobject]@{
            Path  = $bits[1]
            Major = [int]$parts[0]
            Minor = [int]$parts[1]
            Text  = $bits[0]
        }
    } catch { return $null }
}

$chosen = $null
if ($Python) {
    if (-not (Test-Path $Python)) { Die "No python.exe at '$Python'." }
    $chosen = Test-PythonCandidate -Exe $Python
    if (-not $chosen) { Die "'$Python' did not run as a Python interpreter." }
    if ($chosen.Major -ne 3 -or $chosen.Minor -lt 11) {
        Die "'$Python' is Python $($chosen.Text); 3.11 or newer is required."
    }
} else {
    # the py launcher knows about every installed version; ask it first
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($tag in @('-3.13', '-3.12', '-3.11')) {
            $c = Test-PythonCandidate -Exe 'py' -PreArgs @($tag)
            if ($c) { $candidates += $c }
        }
    }
    foreach ($name in @('python', 'python3')) {
        if (Get-Command $name -ErrorAction SilentlyContinue) {
            $c = Test-PythonCandidate -Exe $name
            if ($c) { $candidates += $c }
        }
    }
    $candidates = $candidates | Sort-Object Path -Unique
    $chosen = $candidates | Where-Object { $_.Major -eq 3 -and $_.Minor -ge 11 } |
              Sort-Object Minor -Descending | Select-Object -First 1
    if (-not $chosen -and $candidates) {
        $best = $candidates | Sort-Object Minor -Descending | Select-Object -First 1
        Die "Found Python $($best.Text), but 3.11 or newer is required." `
            "Install it from https://www.python.org/downloads/ and tick 'Add python.exe to PATH'."
    }
}
if (-not $chosen) {
    Die "No Python interpreter found." `
        "Install Python 3.11+ from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), then reopen this window."
}
Ok "Python $($chosen.Text) - $($chosen.Path)"

# ---------------------------------------------------------------- 2. venv
Step 2 $total 'Preparing the build environment'
$VenvPy = Join-Path $VenvDir 'Scripts\python.exe'
if (-not (Test-Path $VenvPy)) {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    & $chosen.Path -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Die "Could not create a virtual environment in $VenvDir." `
            "If this is a managed machine, check that the venv module is installed and the path is writable."
    }
    Info "created $VenvDir"
} else {
    Info "reusing $VenvDir (delete build\.venv, or pass -Clean, to start fresh)"
}

# ---------------------------------------------------------------- 3. deps
Step 3 $total 'Installing dependencies'
& $VenvPy -m pip install --upgrade pip setuptools wheel --quiet
if ($LASTEXITCODE -ne 0) { Die "Could not upgrade pip." "Check your network access and any proxy settings." }

& $VenvPy -m pip install -r (Join-Path $Root 'requirements.txt') --quiet
if ($LASTEXITCODE -ne 0) {
    Die "Could not install from requirements.txt." `
        "Behind a corporate proxy, set HTTPS_PROXY, or use: pip install --proxy http://user:pass@proxy:port"
}
& $VenvPy -m pip install pyinstaller --quiet
if ($LASTEXITCODE -ne 0) { Die "Could not install PyInstaller." }

$pyiVer = (& $VenvPy -m PyInstaller --version 2>$null).Trim()
Ok "dependencies ready (PyInstaller $pyiVer)"

# ---------------------------------------------------------------- 4. tests
Step 4 $total 'Running tests'
if ($SkipTests) {
    Warn 'skipped (-SkipTests)'
} else {
    # test_ui needs Playwright + a browser download, which a build box rarely has
    & $VenvPy -m pytest (Join-Path $Root 'tests') -q -k "not test_ui"
    if ($LASTEXITCODE -ne 0) {
        Die "Tests failed - not packaging a broken build." `
            "Run '$VenvPy -m pytest tests -v -k `"not test_ui`"' to see which."
    }
    Ok 'tests passed'
}

# ---------------------------------------------------------------- 5. build
Step 5 $total "Building the executable ($(if ($OneFile) {'single file'} else {'folder'}))"
if (Test-Path $DistDir)  { Remove-Item $DistDir  -Recurse -Force }
if (Test-Path (Join-Path $BuildDir 'VMTracker')) {
    Remove-Item (Join-Path $BuildDir 'VMTracker') -Recurse -Force
}

if ($OneFile) { $env:ONEFILE = '1' } else { Remove-Item Env:\ONEFILE -ErrorAction SilentlyContinue }
try {
    Push-Location $Root
    & $VenvPy -m PyInstaller (Join-Path $Root 'packaging\vmtracker.spec') `
        --noconfirm --distpath $DistDir --workpath (Join-Path $BuildDir 'pyi') --log-level WARN
    $rc = $LASTEXITCODE
} finally {
    Pop-Location
    Remove-Item Env:\ONEFILE -ErrorAction SilentlyContinue
}
if ($rc -ne 0) { Die "PyInstaller failed." "Scroll up for the first error; a missing hidden import is the usual cause." }

$ExePath = if ($OneFile) { Join-Path $DistDir 'VMTracker.exe' }
           else          { Join-Path $DistDir 'VMTracker\VMTracker.exe' }
if (-not (Test-Path $ExePath)) { Die "PyInstaller reported success but $ExePath is missing." }

$sizeMb = if ($OneFile) {
    [math]::Round((Get-Item $ExePath).Length / 1MB, 1)
} else {
    [math]::Round(((Get-ChildItem (Join-Path $DistDir 'VMTracker') -Recurse |
        Measure-Object Length -Sum).Sum) / 1MB, 1)
}
Ok "$ExePath ($sizeMb MB)"

# ---------------------------------------------------------------- 6. smoke test
Step 6 $total 'Smoke-testing the built executable'
if ($NoSmokeTest) {
    Warn 'skipped (-NoSmokeTest)'
} else {
    $SmokeData = Join-Path $env:TEMP ("vmtracker-smoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $SmokeData | Out-Null
    $proc = $null
    $prevDataDir = $env:VM_TRACKER_DATA_DIR
    try {
        # the child inherits this process's environment, which works on 5.1 too
        $env:VM_TRACKER_DATA_DIR = $SmokeData
        $proc = Start-Process -FilePath $ExePath `
            -ArgumentList '--port', $SmokePort, '--no-banner' `
            -PassThru -WindowStyle Hidden

        $ready = $false
        foreach ($attempt in 1..40) {          # onefile needs time to unpack
            Start-Sleep -Milliseconds 750
            if ($proc.HasExited) { break }
            try {
                $r = Invoke-WebRequest "http://127.0.0.1:$SmokePort/api/health" `
                        -UseBasicParsing -TimeoutSec 3
                if ($r.StatusCode -eq 200) { $ready = $true; break }
            } catch { }
        }

        if ($proc.HasExited) {
            Die "The built exe exited immediately (code $($proc.ExitCode))." `
                "Run it by hand to see the error: $ExePath"
        }
        if (-not $ready) {
            Die "The exe started but never answered on port $SmokePort." `
                "Something may already hold that port, or a bundled dependency is missing."
        }

        $health  = (Invoke-WebRequest "http://127.0.0.1:$SmokePort/api/health" -UseBasicParsing).Content | ConvertFrom-Json
        $console = Invoke-WebRequest "http://127.0.0.1:$SmokePort/" -UseBasicParsing
        $css     = Invoke-WebRequest "http://127.0.0.1:$SmokePort/static/app.css" -UseBasicParsing
        if ($console.StatusCode -ne 200 -or $css.StatusCode -ne 200) {
            Die "The API answered but the web console did not." `
                "The web\ folder may not have been bundled - check the datas list in packaging\vmtracker.spec."
        }
        Ok "API healthy (schema v$($health.schema_version)), console and assets served"
    } finally {
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        if ($null -eq $prevDataDir) { Remove-Item Env:\VM_TRACKER_DATA_DIR -ErrorAction SilentlyContinue }
        else { $env:VM_TRACKER_DATA_DIR = $prevDataDir }
        Remove-Item $SmokeData -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- 7. installer
$IssPath = $null
if ($Installer) {
    Step 7 $total 'Building the installer'
    $isccCandidates = @(
        (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source,
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    if (-not $isccCandidates) {
        Warn 'Inno Setup 6 not found - skipping the installer.'
        Info 'Get it from https://jrsoftware.org/isdl.php, then re-run with -Installer.'
    } elseif ($OneFile) {
        Warn 'The installer packages the folder build; skipping it for -OneFile.'
        Info 'Run without -OneFile to produce an installer.'
    } else {
        & $isccCandidates[0] (Join-Path $Root 'packaging\installer.iss')
        if ($LASTEXITCODE -ne 0) { Die "Inno Setup failed." }
        $IssPath = Get-ChildItem $OutputDir -Filter '*.exe' -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($IssPath) { Ok $IssPath.FullName }
    }
}

# ---------------------------------------------------------------- done
$elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds)
Write-Host ''
Write-Host "  Build complete in ${elapsed}s" -ForegroundColor Green
Write-Host ''
Write-Host "  Executable : $ExePath"
if (-not $OneFile) {
    Write-Host "  Ship        : the whole dist\VMTracker folder, not the exe alone"
}
if ($IssPath) { Write-Host "  Installer  : $($IssPath.FullName)" }
Write-Host ''
Write-Host '  Run it      : ' -NoNewline; Write-Host $ExePath -ForegroundColor Cyan
Write-Host '  Then open   : ' -NoNewline; Write-Host 'http://localhost:9797/' -ForegroundColor Cyan
Write-Host '  Sign in     : admin / admin  (you will be made to change it)'
Write-Host ''
Write-Host '  To reach it from other machines, allow the port once:' -ForegroundColor DarkGray
Write-Host '    netsh advfirewall firewall add rule name="VM Tracker" dir=in action=allow protocol=TCP localport=9797' -ForegroundColor DarkGray
Write-Host ''
exit 0
