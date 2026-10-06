# Windows Build Guide

This repo does not reliably run from a prebuilt `build\bin\cypher.exe` copied from another machine. On each Windows machine, rebuild `cypher.exe`, the BLS static libraries, and the MinGW runtime DLL set locally so they all match.

## Prerequisites

Install these first:

- `git` on `PATH`
- `go` on `PATH`
- Python 3 on `PATH`
- MSYS2 installed at `C:\msys64`
- MSYS2 `mingw64` toolchain and OpenSSL/GMP runtime packages

Recommended install commands:

```powershell
winget install --accept-package-agreements --accept-source-agreements --silent Git.Git GoLang.Go Python.Python.3.12
```

Install the required MSYS2 packages:

```powershell
C:\msys64\usr\bin\bash.exe -lc "pacman -Sy --noconfirm make mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl mingw-w64-x86_64-gmp"
```

## Clone And Prepare The Repo

Clone the repo and switch to the branch you actually want to run:

```powershell
git clone https://github.com/CypherTroopers/cypher.git
cd cypher
git fetch --all
git checkout ecdsa_1.1_test_colossus-Xv2test
```

## Build On Windows

Run the dedicated Windows build script from the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File .\build\build_windows.ps1
```

That script does all of the Windows-specific work needed for this codebase:

- creates a temporary GOPATH workspace under `build\_gopath`
- fetches the missing third-party Go dependencies used by this GOPATH-mode branch
- clones Herumi BLS sources into `build\herumi-bls`
- rebuilds `libmcl.a` and `libbls256.a` with the local `mingw64` toolchain
- copies the rebuilt Windows BLS archives into `crypto\bls\lib\win`
- builds `build\bin\cypher.exe`
- copies the required MinGW/OpenSSL/GMP runtime DLLs into `build\bin`
- verifies the executable with `.\build\bin\cypher.exe version`

If the script finishes successfully, the runnable binary is:

```text
build\bin\cypher.exe
```

## Verify The Binary

You can manually verify it at any time with:

```powershell
.\build\bin\cypher.exe version
```

Expected output includes lines like:

```text
Cypher
Version: 1.9.20-stable
Operating System: windows
```

## Run The Node

Initialize the chain data:

```powershell
.\build\bin\cypher.exe --datadir chaindbname init .\genesis.json
```

Then start the node:

```powershell
./build/bin/cypher \
  --verbosity 4 \
  --rnetport 7200 \
  --syncmode full \
  --nat extip:$(curl -4 -s ifconfig.io) \
  --ws \
  --ws.addr 0.0.0.0 \
  --ws.port 9251 \
  --ws.origins "*" \
  --metrics \
  --http \
  --http.addr 0.0.0.0 \
  --http.port 8000 \
  --http.api eth,web3,net,txpool \
  --http.corsdomain "*" \
  --port 6000 \
  --datadir chaindbname \
  --networkid 123678 \
  --gcmode archive \
  --bootnodes enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@149.102.156.210:6000 \
console
```

## Troubleshooting

- If PowerShell says `build_windows.ps1` does not exist, you are either on the wrong branch or using an old checkout. This repo now includes the script at `build\build_windows.ps1`.
- If Python is missing, install it first and reopen PowerShell so `python` or a real Python executable is available.
- If MSYS2 packages are missing, rerun the `pacman` command above.
- If the build fails after switching branches, rerun `.\build\build_windows.ps1` so the BLS archives are rebuilt for that machine again.
