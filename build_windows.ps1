[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$bashExe = "C:\msys64\usr\bin\bash.exe"
$mingwBin = "C:\msys64\mingw64\bin"
$gopathRoot = Join-Path $repoRoot "build\_gopath"
$gocacheRoot = Join-Path $repoRoot "build\_gocache"
$binDir = Join-Path $repoRoot "build\bin"
$herumiRoot = Join-Path $repoRoot "build\herumi-bls"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' is not available on PATH."
    }
}

function Require-Path {
    param(
        [string]$Path,
        [string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label not found at '$Path'."
    }
}

function Resolve-PythonDir {
    $candidates = New-Object System.Collections.Generic.List[string]

    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd -and $pythonCmd.Source -and ($pythonCmd.Source -notmatch "WindowsApps")) {
        $candidates.Add((Split-Path -Parent $pythonCmd.Source))
    }

    $localPythonBin = Join-Path $env:LOCALAPPDATA "Python\bin"
    if (Test-Path -LiteralPath (Join-Path $localPythonBin "python.exe")) {
        $candidates.Add($localPythonBin)
    }

    $programsPython = Join-Path $env:LOCALAPPDATA "Programs\Python"
    if (Test-Path -LiteralPath $programsPython) {
        Get-ChildItem -LiteralPath $programsPython -Directory | ForEach-Object {
            if (Test-Path -LiteralPath (Join-Path $_.FullName "python.exe")) {
                $candidates.Add($_.FullName)
            }
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-Path -LiteralPath (Join-Path $candidate "python.exe")) {
            return $candidate
        }
    }

    throw "Python 3 was not found. Install it first, for example with: winget install --accept-package-agreements --accept-source-agreements --silent Python.Python.3.12"
}

function Convert-ToMsysPath {
    param([string]$WindowsPath)

    $resolved = (Resolve-Path -LiteralPath $WindowsPath).Path
    if ($resolved -match '^([A-Za-z]):\\(.*)$') {
        $drive = $matches[1].ToLowerInvariant()
        $tail = $matches[2] -replace '\\', '/'
        return "/$drive/$tail"
    }
    throw "Cannot convert path '$resolved' to an MSYS path."
}

function Invoke-BashChecked {
    param([string]$Script)

    & $bashExe -lc $Script
    if ($LASTEXITCODE -ne 0) {
        throw "bash command failed with exit code $LASTEXITCODE"
    }
}

function Ensure-GitClone {
    param(
        [string]$Destination,
        [string]$Url,
        [switch]$Recursive
    )

    if (Test-Path -LiteralPath (Join-Path $Destination ".git")) {
        return
    }

    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null

    $args = @("clone", "--depth", "1")
    if ($Recursive) {
        $args += "--recursive"
    }
    $args += @($Url, $Destination)
    & git @args
    if ($LASTEXITCODE -ne 0) {
        throw "git clone failed for $Url"
    }
}

function Ensure-Junction {
    param(
        [string]$Path,
        [string]$Target
    )

    if (Test-Path -LiteralPath $Path) {
        return
    }

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    New-Item -ItemType Junction -Path $Path -Target $Target | Out-Null
}

function Sync-File {
    param(
        [string]$Source,
        [string]$Destination
    )

    $destParent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $destParent | Out-Null

    if (Test-Path -LiteralPath $Destination) {
        $srcHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
        $dstHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
        if ($srcHash -eq $dstHash) {
            return
        }
    }

    try {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
    catch {
        throw "Failed to copy '$Source' to '$Destination'. Close any running cypher.exe processes and try again. $($_.Exception.Message)"
    }
}

Require-Path (Join-Path $repoRoot "build\ci.go") "Repository root"
Require-Path $bashExe "MSYS2 bash"
Require-Path (Join-Path $mingwBin "gcc.exe") "MSYS2 mingw64 gcc"
Require-Path (Join-Path $mingwBin "g++.exe") "MSYS2 mingw64 g++"
Require-Command "git"
Require-Command "go"

$pythonDir = Resolve-PythonDir
$repoMsys = Convert-ToMsysPath $repoRoot
$herumiMsys = Convert-ToMsysPath $herumiRoot
$pythonMsys = Convert-ToMsysPath $pythonDir

Write-Step "Preparing local build directories"
New-Item -ItemType Directory -Force -Path $gopathRoot, $gocacheRoot, $binDir | Out-Null
$repoLink = Join-Path $gopathRoot "src\github.com\cypherium\cypher"
Ensure-Junction -Path $repoLink -Target $repoRoot

Write-Step "Fetching GOPATH-mode Go dependencies"
$gopathSrc = Join-Path $gopathRoot "src"
$deps = @(
    @{ Path = "github.com\VictoriaMetrics\fastcache"; Url = "https://github.com/VictoriaMetrics/fastcache.git" },
    @{ Path = "github.com\shirou\gopsutil"; Url = "https://github.com/shirou/gopsutil.git" },
    @{ Path = "golang.org\x\sys"; Url = "https://github.com/golang/sys.git" },
    @{ Path = "github.com\dlclark\regexp2"; Url = "https://github.com/dlclark/regexp2.git" },
    @{ Path = "github.com\go-sourcemap\sourcemap"; Url = "https://github.com/go-sourcemap/sourcemap.git" },
    @{ Path = "github.com\yusufpapurcu\wmi"; Url = "https://github.com/yusufpapurcu/wmi.git" },
    @{ Path = "github.com\go-ole\go-ole"; Url = "https://github.com/go-ole/go-ole.git" }
)
foreach ($dep in $deps) {
    Ensure-GitClone -Destination (Join-Path $gopathSrc $dep.Path) -Url $dep.Url
}

Write-Step "Cloning Herumi BLS sources"
Ensure-GitClone -Destination $herumiRoot -Url "https://github.com/herumi/bls.git" -Recursive
& git -C $herumiRoot submodule update --init --recursive
if ($LASTEXITCODE -ne 0) {
    throw "Failed to update Herumi submodules."
}

Write-Step "Rebuilding Windows BLS static libraries with local mingw64"
$mclBuild = @"
export PATH='$pythonMsys':/mingw64/bin:/usr/bin:`$PATH
cd '$herumiMsys/mcl'
make clean
rm -f src/bint_switch.hpp src/llvm_proto.hpp
python3 src/gen_llvm_proto.py > src/llvm_proto.hpp
make -j4 OS=mingw64 lib/libmcl.a MCL_FP_BIT=256 MCL_FR_BIT=256
"@
Invoke-BashChecked $mclBuild

$blsBuild = @"
export PATH='$pythonMsys':/mingw64/bin:/usr/bin:`$PATH
cd '$herumiMsys'
rm -f obj/*.d obj/*.o lib/libbls256.a
make -j4 MCL_FP_BIT=256 MCL_FR_BIT=256 lib/libbls256.a
"@
Invoke-BashChecked $blsBuild

Sync-File -Source (Join-Path $herumiRoot "lib\libbls256.a") -Destination (Join-Path $repoRoot "crypto\bls\lib\win\libbls256.a")
Sync-File -Source (Join-Path $herumiRoot "mcl\lib\libmcl.a") -Destination (Join-Path $repoRoot "crypto\bls\lib\win\libmcl.a")

Write-Step "Building cypher.exe"
$buildEnv = @{
    Path        = "$mingwBin;$env:Path"
    GOPATH      = $gopathRoot
    GOCACHE     = $gocacheRoot
    GO111MODULE = "off"
    CGO_ENABLED = "1"
    CC          = (Join-Path $mingwBin "gcc.exe")
    CXX         = (Join-Path $mingwBin "g++.exe")
}
foreach ($pair in $buildEnv.GetEnumerator()) {
    Set-Item -Path "Env:$($pair.Key)" -Value $pair.Value
}

Push-Location $repoLink
try {
    & go build -o "build\bin\cypher.exe" ".\cmd\cypher"
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed."
    }
}
finally {
    Pop-Location
}

Write-Step "Copying runtime DLLs"
$dlls = @(
    "libcrypto-3-x64.dll",
    "libgmp-10.dll",
    "libstdc++-6.dll",
    "libgcc_s_seh-1.dll",
    "libwinpthread-1.dll"
)
foreach ($dll in $dlls) {
    Sync-File -Source (Join-Path $mingwBin $dll) -Destination (Join-Path $binDir $dll)
}

Write-Step "Verifying cypher.exe"
& (Join-Path $binDir "cypher.exe") version
if ($LASTEXITCODE -ne 0) {
    throw "cypher.exe version check failed."
}

Write-Host ""
Write-Host "Windows build completed successfully."
Write-Host "Binary: $binDir\cypher.exe"
