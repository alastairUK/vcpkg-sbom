# Build a standalone vcpkg-sbom.exe using PyInstaller.
# Run from the repo root: .\build.ps1
# Optional: .\build.ps1 -OneDir   (folder output, faster startup)

param(
    [switch]$OneDir
)

$ErrorActionPreference = "Stop"

# Ensure PyInstaller is available
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "Installing PyInstaller..."
    pip install pyinstaller
}

$bundleFlag = if ($OneDir) { "--onedir" } else { "--onefile" }

Write-Host "Building vcpkg-sbom.exe ($bundleFlag)..."

pyinstaller `
    $bundleFlag `
    --name vcpkg-sbom `
    --console `
    --collect-all spdx_tools `
    --collect-all license_expression `
    --hidden-import spdx_tools `
    vcpkg_sbom/__init__.py

if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller failed."
    exit $LASTEXITCODE
}

$outPath = if ($OneDir) { "dist\vcpkg-sbom\" } else { "dist\vcpkg-sbom.exe" }
Write-Host "Done. Output: $outPath"
