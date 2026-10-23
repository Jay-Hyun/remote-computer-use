# rcu installer (Windows, PowerShell 5.1+).
#   irm https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.ps1 | iex
#
# Env: RCU_VERSION (default: latest), RCU_INSTALL_DIR (default: %LOCALAPPDATA%\rcu\bin),
#      RCU_SKIP_SKILLS=1 (binary only), RCU_BASE_URL / RCU_SKILL_URL (testing).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'Jay-Hyun/remote-computer-use'
$Version = if ($env:RCU_VERSION) { $env:RCU_VERSION } else { 'latest' }
$Dest = if ($env:RCU_INSTALL_DIR) { $env:RCU_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'rcu\bin' }

if ($env:RCU_BASE_URL) { $Base = $env:RCU_BASE_URL }
elseif ($Version -eq 'latest') { $Base = "https://github.com/$Repo/releases/latest/download" }
else { $Base = "https://github.com/$Repo/releases/download/$Version" }

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
$Asset = 'rcu-x86_64-pc-windows-msvc.zip'

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("rcu-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    Write-Host "Downloading $Asset ($Version)..."
    Invoke-WebRequest "$Base/$Asset" -OutFile (Join-Path $Tmp $Asset)
    Invoke-WebRequest "$Base/SHA256SUMS" -OutFile (Join-Path $Tmp 'SHA256SUMS')

    $line = Get-Content (Join-Path $Tmp 'SHA256SUMS') | Where-Object { $_ -match "  $([regex]::Escape($Asset))$" } | Select-Object -First 1
    if (-not $line) { throw "no checksum for $Asset in SHA256SUMS" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash (Join-Path $Tmp $Asset) -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum mismatch for $Asset (expected $expected, got $actual)" }

    Expand-Archive (Join-Path $Tmp $Asset) -DestinationPath $Tmp -Force
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    Copy-Item (Join-Path $Tmp 'rcu.exe') (Join-Path $Dest 'rcu.exe') -Force
    Write-Host "Installed $Dest\rcu.exe"
} finally {
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $Dest) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$Dest", 'User')
    $env:Path = "$env:Path;$Dest"
    Write-Host "Added $Dest to your user PATH (new terminals pick it up)."
}

try { & (Join-Path $Dest 'rcu.exe') init } catch { Write-Host "Note: could not create the default policy; run 'rcu init' yourself." }

if ($env:RCU_SKIP_SKILLS -ne '1') {
    if (Get-Command claude -ErrorAction SilentlyContinue) {
        try {
            claude plugin marketplace add $Repo | Out-Null
            claude plugin install remote-computer-use@remote-computer-use | Out-Null
            Write-Host 'Installed the Claude Code plugin.'
        } catch {
            Write-Host 'Note: could not install the Claude Code plugin automatically. In Claude Code run:'
            Write-Host "  /plugin marketplace add $Repo"
            Write-Host '  /plugin install remote-computer-use@remote-computer-use'
        }
    }
    $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
    if ((Get-Command codex -ErrorAction SilentlyContinue) -or (Test-Path $CodexHome)) {
        $ref = if ($Version -eq 'latest') { 'main' } else { $Version }
        $SkillUrl = if ($env:RCU_SKILL_URL) { $env:RCU_SKILL_URL } else { "https://raw.githubusercontent.com/$Repo/$ref/plugin/skills/remote-computer-use/SKILL.md" }
        $SkillDir = Join-Path $CodexHome 'skills\remote-computer-use'
        New-Item -ItemType Directory -Path $SkillDir -Force | Out-Null
        try {
            Invoke-WebRequest $SkillUrl -OutFile (Join-Path $SkillDir 'SKILL.md')
            Write-Host 'Installed the Codex skill.'
        } catch { Write-Host "Note: could not download the Codex skill from $SkillUrl" }
    }
}

Write-Host ''
Write-Host 'Next:'
Write-Host '  - Edit the policy printed above (everything is off by default), then:  rcu policy-check'
Write-Host '  - On the PC you want to control:  rcu serve      (needs Tailscale; keep the terminal open to approve)'
Write-Host '  - On this PC:                     rcu pair <name> <ip:port> <code>'
