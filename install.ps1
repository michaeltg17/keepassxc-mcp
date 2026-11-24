# Installs the latest keepassxc-mcp release binary for this Windows machine.
#
# What it does: picks the right Release asset for your CPU, downloads it plus
# SHA256SUMS.txt from https://github.com/michaeltg17/keepassxc-mcp/releases/latest,
# verifies the checksum, and installs keepassxc-mcp.exe into
# $env:LOCALAPPDATA\Programs\keepassxc-mcp, adding it to your user PATH.
# It does NOT install keepassxc-cli - that is KeePassXC's own binary and this
# tool refuses to run without it (see the wiki: Setup-and-Use).
#
# Pre-releases (beta verification builds) are NOT installed by default - the
# "latest" endpoint excludes them. To install the newest beta on purpose:
#   $env:KEEPASSXC_MCP_PRERELEASE = '1'; irm https://raw.githubusercontent.com/michaeltg17/keepassxc-mcp/main/install.ps1 | iex
#
# Usage:  irm https://raw.githubusercontent.com/michaeltg17/keepassxc-mcp/main/install.ps1 | iex
#     or: .\install.ps1        (from a clone)
$ErrorActionPreference = 'Stop'

$repo = 'michaeltg17/keepassxc-mcp'
$dir = Join-Path $env:LOCALAPPDATA 'Programs\keepassxc-mcp'

if (Get-Process -Name 'keepassxc-mcp' -ErrorAction SilentlyContinue) {
    Write-Error 'keepassxc-mcp is running (an MCP host holds the exe). Stop just that server — e.g. disable the keepassxc MCP server in your agent settings (fully closing the agent also works) — then re-run this installer.'
    exit 1
}

$rid = switch (${env:PROCESSOR_ARCHITECTURE}) {
    'AMD64' { 'win-x64' }
    'ARM64' { 'win-arm64' }
    default { Write-Error "Unsupported CPU: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}

$prerelease = $env:KEEPASSXC_MCP_PRERELEASE -eq '1'
if ($prerelease) {
    # Deliberately not Invoke-RestMethod: on some stacks it hands back a single
    # odd object for a JSON array, which silently breaks the filter below.
    # Explicit text -> ConvertFrom-Json, @() forces a real pipeline array.
    $resp = Invoke-WebRequest "https://api.github.com/repos/$repo/releases?per_page=30" -UseBasicParsing
    $all = @($resp.Content | ConvertFrom-Json)
    $latest = $all | Where-Object { $_.prerelease -and -not $_.draft } | Select-Object -First 1
} else {
    $latest = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
}
$tag = if ($latest) { $latest.tag_name } else { $null }
if (-not $tag) { Write-Error "Could not determine the latest release tag (prerelease opt-in: $prerelease)."; exit 1 }

$version = $tag.TrimStart('v')
$asset = "keepassxc-mcp-$version-$rid.zip"
$base = "https://github.com/$repo/releases/download/$tag"
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "keepassxc-mcp-install-$([guid]::NewGuid())")
try {
    if ($prerelease) { Write-Host "Latest PRERELEASE: $tag" } else { Write-Host "Latest release: $tag" }
    try {
        Invoke-WebRequest "$base/$asset" -OutFile (Join-Path $tmp $asset)
    } catch {
        # Releases before v0.2.2 used unversioned asset names.
        $asset = "keepassxc-mcp-$rid.zip"
        Invoke-WebRequest "$base/$asset" -OutFile (Join-Path $tmp $asset)
    }
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
