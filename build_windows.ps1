# Compatibility entry point. The pinned, module-based build is shared with
# Linux/macOS through make cypher; install MSYS2/build prerequisites separately.
[CmdletBinding()]
param([string]$MsysRoot = "C:\msys64")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BuildExitCode = 1
$BuildProcess = $null
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw "build_windows.ps1 requires Windows and MSYS2 MINGW64."
    }

    $RepoRoot = $PSScriptRoot
    $BashExe = Join-Path $MsysRoot "usr\bin\bash.exe"
    foreach ($RequiredPath in @(
        $BashExe,
        (Join-Path $RepoRoot "build\build-cypher.sh"),
        (Join-Path $RepoRoot "Makefile")
    )) {
        if (!(Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
            throw "Required build file not found: $RequiredPath"
        }
    }

    $BuildStart = New-Object System.Diagnostics.ProcessStartInfo
    $BuildStart.FileName = $BashExe
    $BuildStart.Arguments = "--noprofile --norc -s --"
    $BuildStart.UseShellExecute = $false
    $BuildStart.RedirectStandardInput = $true
    $BuildStart.WorkingDirectory = $RepoRoot
    # Environment changes are confined to the child. Pass paths as data, never
    # interpolate them into shell source or change the caller's cwd/GOPATH/PATH.
    $BuildStart.EnvironmentVariables["CYPHER_WINDOWS_BUILD_REPO"] = $RepoRoot
    $BuildStart.EnvironmentVariables["MSYSTEM"] = "MINGW64"
    $BuildStart.EnvironmentVariables["PATH"] = (
        (Join-Path $MsysRoot "mingw64\bin") + ";" +
        (Join-Path $MsysRoot "usr\bin") + ";" + $env:PATH
    )
    $BuildScript = @'
set -Eeuo pipefail
cd -- "$(cygpath -u "$CYPHER_WINDOWS_BUILD_REPO")"
exec make cypher
'@

    $BuildProcess = New-Object System.Diagnostics.Process
    $BuildProcess.StartInfo = $BuildStart
    if (!$BuildProcess.Start()) {
        throw "Unable to start MSYS2 bash."
    }
    try {
        # Git may check this file out with CRLF, which bash treats as literal
        # characters. Also avoid StreamWriter's Windows CRLF terminator.
        $BuildProcess.StandardInput.Write($BuildScript.Replace("`r`n", "`n") + "`n")
    }
    finally {
        try {
            $BuildProcess.StandardInput.Close()
        }
        finally {
            $BuildProcess.WaitForExit()
            $BuildExitCode = $BuildProcess.ExitCode
        }
    }
}
catch {
    [Console]::Error.WriteLine("ERROR: " + $_.Exception.Message)
    if ($BuildExitCode -eq 0) { $BuildExitCode = 1 }
}
finally {
    if ($null -ne $BuildProcess) { $BuildProcess.Dispose() }
}
exit $BuildExitCode
