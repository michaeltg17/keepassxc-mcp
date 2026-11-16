# Installs the latest keepassxc-mcp release binary for this Windows machine.
#
# What it does: picks the right Release asset for your CPU, downloads it plus
# SHA256SUMS.txt from https://github.com/michaeltg17/keepassxc-mcp/releases/latest,
# verifies the checksum, and installs keepassxc-mcp.exe into
# $env:LOCALAPPDATA\Programs\keepassxc-mcp, adding it to your user PATH.
# It does NOT install keepassxc-cli - that is KeePassXC's own binary and this
# tool refuses to run without it (see the wiki: Setup-and-Use).
#
# Usage:  irm https://raw.githubusercontent.com/michaeltg17/keepassxc-mcp/main/install.ps1 | iex
#     or: .\install.ps1        (from a clone)
$ErrorActionPreference = 'Stop'

$repo = 'michaeltg17/keepassxc-mcp'
$dir = Join-Path $env:LOCALAPPDATA 'Programs\keepassxc-mcp'

if (Get-Process -Name 'keepassxc-mcp' -ErrorAction SilentlyContinue) {
    Write-Error 'keepassxc-mcp is running (an MCP host holds the exe). Close your agent/OpenCode first, then re-run this installer.'
    exit 1
}

$rid = switch (${env:PROCESSOR_ARCHITECTURE}) {
    'AMD64' { 'win-x64' }
    'ARM64' { 'win-arm64' }
    default { Write-Error "Unsupported CPU: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}

$latest = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$tag = $latest.tag_name
if (-not $tag) { Write-Error 'Could not determine the latest release tag.'; exit 1 }

$asset = "keepassxc-mcp-$rid.zip"
$base = "https://github.com/$repo/releases/download/$tag"
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "keepassxc-mcp-install-$([guid]::NewGuid())")
try {
    Write-Host "Latest release: $tag"
    Invoke-WebRequest "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile (Join-Path $tmp 'SHA256SUMS.txt')

    Write-Host 'Verifying checksum...'
    $expected = ((Get-Content (Join-Path $tmp 'SHA256SUMS.txt') |
        Where-Object { $_ -match " $([regex]::Escape($asset))$" }) -split '\s+')[0]
    $actual = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Write-Error "Checksum verification FAILED (expected $expected, got $actual). Nothing installed."
        exit 1
    }

    Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $dir -Force

    # Add to the user PATH (not the machine PATH: no admin rights needed).
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $dir) {
        [Environment]::SetEnvironmentVariable('Path', "$dir;$userPath", 'User')
        Write-Host "Added $dir to your user PATH (new terminals pick it up)."
    }

    Write-Host "Installed: $dir\keepassxc-mcp.exe"
    if (-not (Get-Command keepassxc-cli -ErrorAction SilentlyContinue)) {
        Write-Host ''
        Write-Host 'WARNING: keepassxc-cli was not found on your PATH. keepassxc-mcp needs'
        Write-Host 'it (it ships with KeePassXC: https://keepassxc.org/download/#windows).'
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
