<#
.SYNOPSIS
    Authenticode-sign the Sentinel Scan binaries and installer.

.DESCRIPTION
    Signs every .exe and .dll in the PyInstaller output plus the Inno Setup
    installer, then verifies each signature.

    Why signing matters more than usual for this project: an unsigned
    security scanner that reads every file on the disk and quarantines some
    of them is indistinguishable, to SmartScreen and to a cautious user,
    from the thing it is trying to catch. Ship it signed.

    Two credential sources are supported:

      * A PFX file plus password (development and self-signed testing).
      * A certificate in the Windows store, by thumbprint (recommended:
        with a hardware token or an HSM the key never leaves the device).

.PARAMETER Path
    Directory to sign. Defaults to dist\sentinel.

.PARAMETER Thumbprint
    SHA-1 thumbprint of a certificate in the current user's store.

.PARAMETER PfxPath
    Path to a .pfx file. Requires -PfxPassword.

.PARAMETER PfxPassword
    Password for the PFX, as a SecureString.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server. Timestamping is not optional: without it
    every signature becomes invalid the day the certificate expires.

.PARAMETER Verify
    Only verify existing signatures; sign nothing.

.EXAMPLE
    .\sign.ps1 -Thumbprint A1B2C3D4E5F6...

.EXAMPLE
    $pw = Read-Host -AsSecureString
    .\sign.ps1 -PfxPath .\codesign.pfx -PfxPassword $pw

.EXAMPLE
    .\sign.ps1 -Verify
#>

[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [string]$Path = (Join-Path $PSScriptRoot '..\..\dist\sentinel'),

    [Parameter(ParameterSetName = 'Thumbprint')]
    [string]$Thumbprint,

    [Parameter(ParameterSetName = 'Pfx', Mandatory = $true)]
    [string]$PfxPath,

    [Parameter(ParameterSetName = 'Pfx', Mandatory = $true)]
    [System.Security.SecureString]$PfxPassword,

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [switch]$Verify
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step($Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message)   { Write-Host "    $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "    $Message" -ForegroundColor Yellow }

# --- locate the files -------------------------------------------------

if (-not (Test-Path $Path)) {
    throw "Nothing to sign at '$Path'. Build first: pyinstaller packaging/windows/sentinel.spec"
}

$resolved = (Resolve-Path $Path).Path
Write-Step "Collecting binaries under $resolved"

$targets = @(Get-ChildItem -Path $resolved -Recurse -Include '*.exe', '*.dll', '*.pyd' -File)

# Include the installer if it has been built.
$installerDir = Join-Path $PSScriptRoot 'Output'
if (Test-Path $installerDir) {
    $targets += @(Get-ChildItem -Path $installerDir -Filter '*.exe' -File)
}

if ($targets.Count -eq 0) {
    throw "No .exe, .dll or .pyd files found under '$resolved'."
}
Write-Ok "$($targets.Count) file(s) found"

# --- verify-only ------------------------------------------------------

if ($Verify) {
    Write-Step 'Verifying signatures'
    $unsigned = 0
    $valid = 0

    foreach ($file in $targets) {
        $signature = Get-AuthenticodeSignature -FilePath $file.FullName
        switch ($signature.Status) {
            'Valid' {
                $valid++
            }
            'NotSigned' {
                $unsigned++
                Write-Warn "unsigned: $($file.Name)"
            }
            default {
                $unsigned++
                Write-Warn "$($signature.Status): $($file.Name)"
            }
        }
    }

    Write-Host ''
    Write-Ok "$valid valid, $unsigned not valid"
    if ($unsigned -gt 0) { exit 1 }
    exit 0
}

# --- find signtool ----------------------------------------------------

Write-Step 'Locating signtool.exe'
$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source

if (-not $signtool) {
    # Fall back to the newest Windows SDK copy.
    $sdkRoot = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path $sdkRoot) {
        $candidate = Get-ChildItem -Path $sdkRoot -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'x64' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { $signtool = $candidate.FullName }
    }
}

if (-not $signtool) {
    throw 'signtool.exe not found. Install the Windows SDK (Signing Tools component).'
}
Write-Ok $signtool

# --- build the argument list -----------------------------------------

$signArgs = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampUrl, '/v')

if ($PSCmdlet.ParameterSetName -eq 'Pfx') {
    if (-not (Test-Path $PfxPath)) { throw "PFX not found: $PfxPath" }
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
    $signArgs += @('/f', (Resolve-Path $PfxPath).Path, '/p', $plain)
    Write-Step "Signing with PFX $PfxPath"
}
elseif ($Thumbprint) {
    $signArgs += @('/sha1', $Thumbprint)
    Write-Step "Signing with certificate $Thumbprint"
}
else {
    # Let signtool pick the single best code-signing certificate available.
    $signArgs += '/a'
    Write-Step 'Signing with the best available certificate (/a)'
}

# --- sign -------------------------------------------------------------

$signed = 0
$failed = @()

foreach ($file in $targets) {
    $existing = Get-AuthenticodeSignature -FilePath $file.FullName
    if ($existing.Status -eq 'Valid') {
        Write-Host "    skip (already signed): $($file.Name)"
        continue
    }

    & $signtool @signArgs $file.FullName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $signed++
        Write-Ok "signed: $($file.Name)"
    }
    else {
        $failed += $file.Name
        Write-Warn "FAILED: $($file.Name) (signtool exit $LASTEXITCODE)"
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Pfx') {
    # Do not leave the password in memory longer than necessary.
    $plain = $null
    [GC]::Collect()
}

# --- verify what we signed -------------------------------------------

Write-Host ''
Write-Step 'Verifying'
$invalid = 0
foreach ($file in $targets) {
    $signature = Get-AuthenticodeSignature -FilePath $file.FullName
    if ($signature.Status -ne 'Valid') {
        $invalid++
        Write-Warn "$($signature.Status): $($file.Name)"
    }
}

Write-Host ''
Write-Ok "$signed newly signed, $invalid not valid"

if ($failed.Count -gt 0) {
    Write-Warn "Failures: $($failed -join ', ')"
    exit 1
}
if ($invalid -gt 0) { exit 1 }

Write-Host ''
Write-Ok 'All binaries carry a valid, timestamped signature.'
exit 0
