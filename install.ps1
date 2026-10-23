# rcu installer (Windows, PowerShell 5.1+).
#   irm https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.ps1 | iex
#
# Env: RCU_VERSION (default: latest), RCU_INSTALL_DIR (default: %LOCALAPPDATA%\rcu\bin),
#      RCU_SKIP_SKILLS=1 (binary only),
#      RCU_BASE_URL (mirror/testing; must be https:// unless RCU_ALLOW_INSECURE=1).
function Install-Rcu {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $Repo = 'Jay-Hyun/remote-computer-use'
    $Version = if ($env:RCU_VERSION) { $env:RCU_VERSION } else { 'latest' }
    $Dest = if ($env:RCU_INSTALL_DIR) { $env:RCU_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'rcu\bin' }
    $Insecure = ($env:RCU_ALLOW_INSECURE -eq '1')

    if ($env:RCU_BASE_URL) {
        $Base = $env:RCU_BASE_URL
        if (-not $Base.StartsWith('https://')) {
            if (-not $Insecure) { throw 'RCU_BASE_URL must start with https:// (set RCU_ALLOW_INSECURE=1 only for local testing)' }
            Write-Warning 'using a non-https base URL; checksums fetched from it prove nothing.'
        }
    }
    elseif ($Version -eq 'latest') { $Base = "https://github.com/$Repo/releases/latest/download" }
    else { $Base = "https://github.com/$Repo/releases/download/$Version" }

    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    $Asset = 'rcu-x86_64-pc-windows-msvc.zip'

    $Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("rcu-" + [System.Guid]::NewGuid())
    New-Item -ItemType Directory -Path $Tmp | Out-Null
    try {
        $sumsPath = Join-Path $Tmp 'SHA256SUMS'
        Write-Host "Downloading rcu ($Version)..."
        Invoke-WebRequest -UseBasicParsing "$Base/SHA256SUMS" -OutFile $sumsPath
        $sums = Get-Content $sumsPath

        # Download a file and verify it against SHA256SUMS. Fails closed.
        function Get-Verified([string]$Name) {
            $path = Join-Path $Tmp $Name
            Invoke-WebRequest -UseBasicParsing "$Base/$Name" -OutFile $path
            $lines = @($sums | Where-Object { $_ -match "  $([regex]::Escape($Name))$" })
            if ($lines.Count -ne 1) { throw "expected exactly one checksum for $Name in SHA256SUMS, found $($lines.Count)" }
            $expected = ($lines[0] -split '\s+')[0].ToLower()
            $actual = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
            if ($expected -ne $actual) { throw "checksum mismatch for $Name (expected $expected, got $actual)" }
            return $path
        }

        $zipPath = Get-Verified $Asset

        # Extract only rcu.exe from the archive.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        New-Item -ItemType Directory -Path $Dest -Force | Out-Null
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -eq 'rcu.exe' } | Select-Object -First 1
            if (-not $entry) { throw 'archive did not contain rcu.exe' }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Dest 'rcu.exe'), $true)
        } finally { $zip.Dispose() }
        Write-Host "Installed $Dest\rcu.exe"

        # Add to the user PATH without flattening %VARS% entries.
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        try {
            $cur = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if (($cur -split ';') -notcontains $Dest) {
                $new = if ($cur) { "$cur;$Dest" } else { $Dest }
                $key.SetValue('Path', $new, [Microsoft.Win32.RegistryValueKind]::ExpandString)
                Write-Host "Added $Dest to your user PATH (open a new terminal, or sign out and in)."
            }
        } finally { $key.Close() }
        $env:Path = "$env:Path;$Dest"

        try { & (Join-Path $Dest 'rcu.exe') init } catch { Write-Host "Note: could not create the default policy; run 'rcu init' yourself." }

        if ($env:RCU_SKIP_SKILLS -ne '1') {
            if (Get-Command claude -ErrorAction SilentlyContinue) {
                # NOTE: this tracks the repository's default branch, not this release.
                claude plugin marketplace add $Repo | Out-Null
                $ok = ($LASTEXITCODE -eq 0)
                if ($ok) { claude plugin install remote-computer-use@remote-computer-use | Out-Null; $ok = ($LASTEXITCODE -eq 0) }
                if ($ok) { Write-Host 'Installed the Claude Code plugin.' }
                else {
                    Write-Host 'Note: could not install the Claude Code plugin automatically. In Claude Code run:'
                    Write-Host "  /plugin marketplace add $Repo"
                    Write-Host '  /plugin install remote-computer-use@remote-computer-use'
                }
            }
            $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
            if ((Get-Command codex -ErrorAction SilentlyContinue) -or (Test-Path $CodexHome)) {
                if ($sums | Where-Object { $_ -match '  SKILL\.md$' }) {
                    $skill = Get-Verified 'SKILL.md'
                    $SkillDir = Join-Path $CodexHome 'skills\remote-computer-use'
                    New-Item -ItemType Directory -Path $SkillDir -Force | Out-Null
                    Copy-Item $skill (Join-Path $SkillDir 'SKILL.md.part') -Force
                    Move-Item (Join-Path $SkillDir 'SKILL.md.part') (Join-Path $SkillDir 'SKILL.md') -Force
                    Write-Host 'Installed the Codex skill.'
                } else { Write-Host 'Note: this release has no SKILL.md asset; skipping the Codex skill.' }
            }
        }
    } finally {
        Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host 'Next:'
    Write-Host '  - Edit the policy printed above (everything is off by default), then:  rcu policy-check'
    Write-Host '  - On the PC you want to control:  rcu serve      (needs Tailscale; approve in the terminal or the dialog)'
    Write-Host '    or start it at every login:     rcu service install'
    Write-Host '  - On this PC:                     rcu pair <name> <ip:port> <code>'
    Write-Host '  - After upgrading a PC that runs the service: rcu service install   (restarts it with the new binary)'
}
Install-Rcu
