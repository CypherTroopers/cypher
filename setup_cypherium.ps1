# setup_cypherium.ps1
# Run with Administrator PowerShell:
# powershell -ExecutionPolicy Bypass -File .\setup_cypherium.ps1 -GenesisFile "$env:USERPROFILE\go\src\github.com\cypherium\cypher\cmd\cypher\genesisLocal.json" -ExpectedChainId 12367

#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$RepoUrl = "https://github.com/CypherTroopers/cypher.git",
    [string]$RepoBranch = "ecdsa_1.1_test_colossus-Xv2test",
    [string]$Gopath = (Join-Path $env:USERPROFILE "go"),
    [ValidateSet("mingw64", "ucrt64")]
    [string]$MsysFlavor = "mingw64",
    [string]$DataDir = "",
    [string]$GenesisFile = "",
    [Int64]$ExpectedChainId = 0,
    [switch]$CleanData,
    [switch]$SkipInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Add-ProcessPath {
    param([string]$PathToAdd)
    if ((Test-Path -LiteralPath $PathToAdd) -and (($env:Path -split ';') -notcontains $PathToAdd)) {
        $env:Path = "$PathToAdd;$env:Path"
    }
}

function Invoke-NativeChecked {
    param(
        [scriptblock]$Command,
        [string]$ErrorMessage
    )
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$ErrorMessage ExitCode=$LASTEXITCODE"
    }
}

function Install-WingetPackage {
    param(
        [string[]]$Ids,
        [string]$Name,
        [string[]]$Commands = @(),
        [string[]]$Paths = @()
    )

    foreach ($command in $Commands) {
        if (Get-Command $command -ErrorAction SilentlyContinue) {
            Write-Host "$Name already installed. Found command: $command"
            return
        }
    }
    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path) {
            Write-Host "$Name already installed. Found path: $path"
            return
        }
    }
    if ($SkipInstall) {
        throw "$Name was not found and -SkipInstall was specified."
    }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget was not found. Update App Installer from Microsoft Store or rerun with -SkipInstall after installing prerequisites manually."
    }

    foreach ($id in $Ids) {
        Write-Host "Installing $Name with winget package id: $id"
        & winget install --id $id -e --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: winget returned $LASTEXITCODE for $id. Trying the next candidate if available."
            continue
        }
        foreach ($path in $Paths) {
            if (Test-Path -LiteralPath $path) { return }
        }
        foreach ($command in $Commands) {
            if (Get-Command $command -ErrorAction SilentlyContinue) { return }
        }
        return
    }

    throw "Failed to install or detect $Name."
}

function Get-GoBinPath {
    $preferred = "C:\Program Files\Go\bin\go.exe"
    if (Test-Path -LiteralPath $preferred) {
        return Split-Path -Parent $preferred
    }
    $cmd = Get-Command go.exe -ErrorAction Stop
    return Split-Path -Parent $cmd.Source
}

function Assert-GoVersionSupported {
    param([string]$GoExe)
    $version = & $GoExe version
    Write-Host $version
    if ($version -notmatch 'go(\d+)\.(\d+)') {
        throw "Could not parse Go version: $version"
    }
    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    if (($major -lt 1) -or (($major -eq 1) -and ($minor -lt 13))) {
        throw "Go 1.13 or newer is required by build/ci.go. Found: $version"
    }
}

function Copy-BLSWindowsLibraries {
    param([string]$CypherDir)
    $src = Join-Path $CypherDir "crypto\bls\lib\win"
    $dst = Join-Path $CypherDir "crypto\bls\lib"
    if (-not (Test-Path -LiteralPath $src)) {
        throw "Windows BLS static library directory not found: $src"
    }
    $libs = Get-ChildItem -LiteralPath $src -Filter "*.a"
    if ($libs.Count -eq 0) {
        throw "No Windows BLS static libraries were found in: $src"
    }
    foreach ($lib in $libs) {
        Copy-Item -LiteralPath $lib.FullName -Destination (Join-Path $dst $lib.Name) -Force
        Write-Host "Copied BLS static library: $($lib.Name)"
    }
}

function Get-ImportedDllNames {
    param(
        [string]$ObjdumpExe,
        [string]$BinaryPath
    )
    if (-not (Test-Path -LiteralPath $ObjdumpExe)) { return @() }
    $lines = & $ObjdumpExe -p $BinaryPath 2>$null | Select-String "DLL Name:"
    return @($lines | ForEach-Object { ($_.Line -replace '^\s*DLL Name:\s*', '').Trim() } | Where-Object { $_ })
}

function Copy-DependentDlls {
    param(
        [string]$BinaryPath,
        [string]$MsysBin,
        [string]$Destination
    )
    $objdump = Join-Path $MsysBin "objdump.exe"
    if (-not (Test-Path -LiteralPath $objdump)) {
        Write-Host "WARNING: objdump.exe was not found. Falling back to known MinGW runtime DLL names."
        $fallback = @("libcrypto-3-x64.dll", "libgmp-10.dll", "libgmpxx-4.dll", "libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll", "zlib1.dll", "libzstd.dll")
        foreach ($dll in $fallback) {
            $src = Join-Path $MsysBin $dll
            if (Test-Path -LiteralPath $src) {
                Copy-Item -LiteralPath $src -Destination (Join-Path $Destination $dll) -Force
                Write-Host "Copied DLL: $dll"
            }
        }
        return
    }

    $queue = New-Object System.Collections.Generic.Queue[string]
    $seen = @{}
    foreach ($dll in (Get-ImportedDllNames -ObjdumpExe $objdump -BinaryPath $BinaryPath)) {
        $queue.Enqueue($dll)
    }

    while ($queue.Count -gt 0) {
        $dll = $queue.Dequeue()
        if ($seen.ContainsKey($dll)) { continue }
        $seen[$dll] = $true

        $src = Join-Path $MsysBin $dll
        if (-not (Test-Path -LiteralPath $src)) {
            Write-Host "Skipping system or non-MSYS DLL: $dll"
            continue
        }

        $dst = Join-Path $Destination $dll
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-Host "Copied DLL: $dll"

        foreach ($child in (Get-ImportedDllNames -ObjdumpExe $objdump -BinaryPath $src)) {
            if (-not $seen.ContainsKey($child)) {
                $queue.Enqueue($child)
            }
        }
    }
}

Write-Step "0/8 Validate PowerShell and administrator context"
if (-not $PSVersionTable.PSVersion) {
    throw "This script must be run with PowerShell, not cmd.exe."
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run this script as Administrator PowerShell."
}

$MsysRoot = "C:\msys64"
$MsysBin = Join-Path $MsysRoot "$MsysFlavor\bin"
$MsysBash = Join-Path $MsysRoot "usr\bin\bash.exe"
$CypherRoot = Join-Path $Gopath "src\github.com\cypherium"
$CypherDir = Join-Path $CypherRoot "cypher"
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    $DataDir = Join-Path $env:LOCALAPPDATA "Cypherium\cypher"
}

Write-Step "1/8 Install or detect required Windows tools"
Install-WingetPackage -Ids @("Git.Git") -Name "Git" -Commands @("git.exe") -Paths @("C:\Program Files\Git\cmd\git.exe")
Install-WingetPackage -Ids @("GoLang.Go") -Name "Go" -Commands @("go.exe") -Paths @("C:\Program Files\Go\bin\go.exe")
Install-WingetPackage -Ids @("MSYS2.MSYS2") -Name "MSYS2" -Paths @($MsysBash)

Add-ProcessPath "C:\Program Files\Git\cmd"
Add-ProcessPath "C:\Program Files\Git\bin"
Add-ProcessPath "C:\Program Files\Go\bin"
Add-ProcessPath $MsysBin

$goBin = Get-GoBinPath
$goExe = Join-Path $goBin "go.exe"
Add-ProcessPath $goBin
Assert-GoVersionSupported -GoExe $goExe
Invoke-NativeChecked -Command { & git --version } -ErrorMessage "git check failed."

Write-Step "2/8 Install MSYS2 CGO dependencies"
if (-not (Test-Path -LiteralPath $MsysBash)) {
    throw "MSYS2 bash not found: $MsysBash"
}
$mingwPrefix = if ($MsysFlavor -eq "ucrt64") { "mingw-w64-ucrt-x86_64" } else { "mingw-w64-x86_64" }
Invoke-NativeChecked -Command { & $MsysBash -lc "pacman -Syuu --noconfirm" } -ErrorMessage "pacman -Syuu failed. Close all MSYS2 terminals and rerun this script."
Invoke-NativeChecked -Command { & $MsysBash -lc "pacman -Suu --noconfirm" } -ErrorMessage "pacman -Suu failed. Close all MSYS2 terminals and rerun this script."
Invoke-NativeChecked -Command { & $MsysBash -lc "pacman -S --needed --noconfirm ${mingwPrefix}-gcc ${mingwPrefix}-binutils ${mingwPrefix}-openssl ${mingwPrefix}-gmp" } -ErrorMessage "MSYS2 dependency install failed."

$cc = Join-Path $MsysBin "gcc.exe"
$cxx = Join-Path $MsysBin "g++.exe"
if (-not (Test-Path -LiteralPath $cc)) { throw "gcc.exe not found: $cc" }
if (-not (Test-Path -LiteralPath $cxx)) { throw "g++.exe not found: $cxx" }
Invoke-NativeChecked -Command { & $cc --version } -ErrorMessage "gcc check failed."

Write-Step "3/8 Clone cypher under the GOPATH import path used by the codebase"
New-Item -ItemType Directory -Force -Path $CypherRoot | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $CypherDir ".git"))) {
    Invoke-NativeChecked -Command { & git clone $RepoUrl $CypherDir } -ErrorMessage "git clone failed."
} else {
    Write-Host "Repository already exists: $CypherDir"
}
Set-Location $CypherDir
Invoke-NativeChecked -Command { & git fetch --all --tags } -ErrorMessage "git fetch failed."
if (-not [string]::IsNullOrWhiteSpace($RepoBranch)) {
    Invoke-NativeChecked -Command { & git checkout $RepoBranch } -ErrorMessage "git checkout failed for branch/ref: $RepoBranch"
}
Write-Host "Git branch:"
& git branch --show-current
Write-Host "Git commit:"
& git rev-parse HEAD

Write-Step "4/8 Configure GOPATH-mode Go and CGO for this process"
$env:GOROOT = Split-Path -Parent $goBin
$env:GOPATH = $Gopath
$env:GO111MODULE = "off"
$env:CGO_ENABLED = "1"
$env:CC = $cc
$env:CXX = $cxx
$env:CGO_CFLAGS_ALLOW = ".*"
$env:CGO_LDFLAGS_ALLOW = ".*"
$env:Path = "$goBin;$MsysBin;C:\Program Files\Git\cmd;C:\Program Files\Git\bin;$env:Path"
Write-Host "GOROOT=$env:GOROOT"
Write-Host "GOPATH=$env:GOPATH"
Write-Host "GO111MODULE=$(go env GO111MODULE)"
Write-Host "CGO_ENABLED=$(go env CGO_ENABLED)"
Write-Host "CC=$env:CC"

Write-Step "5/8 Copy Windows BLS static libraries into the cgo library directory"
Copy-BLSWindowsLibraries -CypherDir $CypherDir

Write-Step "6/8 Build cypher.exe with build/ci.go"
Remove-Item (Join-Path $CypherDir "build\bin") -Recurse -Force -ErrorAction SilentlyContinue
Invoke-NativeChecked -Command { & $goExe run .\build\ci.go install .\cmd\cypher } -ErrorMessage "cypher build failed."
$CypherExe = Join-Path $CypherDir "build\bin\cypher.exe"
if (-not (Test-Path -LiteralPath $CypherExe)) {
    throw "cypher.exe was not created at expected path: $CypherExe"
}
Get-Item -LiteralPath $CypherExe

Write-Step "7/8 Copy MinGW runtime DLLs required by cypher.exe and verify binary"
Copy-DependentDlls -BinaryPath $CypherExe -MsysBin $MsysBin -Destination (Join-Path $CypherDir "build\bin")
$binPath = Join-Path $CypherDir "build\bin"
$env:Path = "$binPath;$MsysBin;$goBin;$env:Path"
Invoke-NativeChecked -Command { & $CypherExe version } -ErrorMessage "cypher.exe version check failed."
Invoke-NativeChecked -Command { & $CypherExe help } -ErrorMessage "cypher.exe help check failed."

Write-Step "8/8 Create data directory and initialize genesis"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
if ([string]::IsNullOrWhiteSpace($GenesisFile)) {
    throw "Pass -GenesisFile explicitly. Example: -GenesisFile `"$CypherDir\cmd\cypher\genesisLocal.json`" -ExpectedChainId 12367"
}
if (-not (Test-Path -LiteralPath $GenesisFile)) {
    throw "Genesis file not found: $GenesisFile"
}
$genesisJson = Get-Content -LiteralPath $GenesisFile -Raw | ConvertFrom-Json
$chainId = $genesisJson.config.chainId
if ($null -eq $chainId) {
    throw "Genesis chainId was not found at config.chainId. GenesisFile=$GenesisFile"
}
if (($ExpectedChainId -ne 0) -and ([Int64]$chainId -ne $ExpectedChainId)) {
    throw "Unexpected genesis chainId. Expected $ExpectedChainId, actual $chainId. GenesisFile=$GenesisFile"
}
Write-Host "Cypher dir: $CypherDir"
Write-Host "Data dir: $DataDir"
Write-Host "Genesis file: $GenesisFile"
Write-Host "Genesis chainId: $chainId"
Get-FileHash -LiteralPath $GenesisFile -Algorithm SHA256 | Format-List

if ($CleanData) {
    Write-Host "CleanData was specified. Removing old chain database files but preserving keystore."
    $cleanTargets = @(
        (Join-Path $DataDir "chaindata"),
        (Join-Path $DataDir "nodes"),
        (Join-Path $DataDir "nodekey"),
        (Join-Path $DataDir "transactions.rlp"),
        (Join-Path $DataDir "triecache"),
        (Join-Path $DataDir "cypher\chaindata"),
        (Join-Path $DataDir "cypher\nodes"),
        (Join-Path $DataDir "cypher\nodekey"),
        (Join-Path $DataDir "cypher\transactions.rlp"),
        (Join-Path $DataDir "cypher\triecache"),
        (Join-Path $DataDir "cypher\colossusX")
    )
    foreach ($target in $cleanTargets) {
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
            Write-Host "Removed: $target"
        }
    }
}

Invoke-NativeChecked -Command { & $CypherExe --datadir $DataDir init $GenesisFile } -ErrorMessage "cypher genesis init failed."

Write-Host ""
Write-Host "Done. Built binary:"
Write-Host "  $CypherExe"
Write-Host "Data directory:"
Write-Host "  $DataDir"
Write-Host ""
Write-Host "Example local start command:"
Write-Host "  .\build\bin\cypher.exe --datadir `"$DataDir`" --networkid $chainId --syncmode full --gcmode archive --http --http.addr 127.0.0.1 --ws --ws.addr 127.0.0.1 console"
Write-Host ""
Write-Host "Example local start command with explicit P2P/RNet/RPC ports:"
Write-Host "  .\build\bin\cypher.exe --datadir `"$DataDir`" --networkid $chainId --syncmode full --gcmode archive --rnetport 7200 --port 6000 --http --http.addr 127.0.0.1 --http.port 8000 --ws --ws.addr 127.0.0.1 --ws.port 9251 console"
