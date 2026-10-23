# End-to-end smoke test of a built rcu.exe on this machine (Windows PowerShell 5.1+ / pwsh).
# Starts a node on 127.0.0.1, pairs a controller, and runs exec / read / write / revoke with
# approvals answered through the node's stdin. Exits non-zero on any failure.
#
#   scripts\smoke.ps1 [path\to\rcu.exe]
param([string]$Rcu = 'target\debug\rcu.exe')
$ErrorActionPreference = 'Stop'
$Rcu = (Resolve-Path $Rcu).Path

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('rcu-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$NodeHome = Join-Path $tmp 'node'
$CtlHome = Join-Path $tmp 'ctl'
$Work = Join-Path $tmp 'work'
New-Item -ItemType Directory -Path $NodeHome, $CtlHome, $Work | Out-Null
Set-Content -Path (Join-Path $Work 'a.txt') -Value 'hello from the node'

$script:nodeLog = New-Object System.Text.StringBuilder
$script:nodeProc = $null
$script:Token = ''

function Fail([string]$msg) {
    Write-Host "SMOKE FAILED: $msg"
    Write-Host '--- node log'
    Write-Host $script:nodeLog.ToString()
    if ($script:nodeProc -and -not $script:nodeProc.HasExited) { $script:nodeProc.Kill() }
    exit 1
}

function Quote-Arg([string]$a) {
    if ($a -match '[\s"]') { return '"' + ($a -replace '"', '\"') + '"' }
    return $a
}

# Run rcu with a given RCU_HOME and optional token; returns @{Code; Out}.
function Run-Rcu([string]$home, [string[]]$CliArgs, [string]$StdinText = '') {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Rcu
    $psi.Arguments = ($CliArgs | ForEach-Object { Quote-Arg $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['RCU_HOME'] = $home
    $psi.EnvironmentVariables['RCU_TOKEN_SMOKE'] = $script:Token
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Write($StdinText)
    $p.StandardInput.Close()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return @{ Code = $p.ExitCode; Out = $out; Err = $err }
}

function Prompt-Count() {
    return ([regex]::Matches($script:nodeLog.ToString(), '\[approval [0-9a-f]+\] [a-z.]+ \(')).Count
}

# Start a controller command that needs approval, answer it on the node, return the result.
function Approved([string]$answer, [string[]]$CliArgs, [string]$StdinText = '') {
    $before = Prompt-Count
    $job = Start-Job -ScriptBlock {
        param($rcu, $home, $token, $argLine, $stdin)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $rcu
        $psi.Arguments = $argLine
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['RCU_HOME'] = $home
        $psi.EnvironmentVariables['RCU_TOKEN_SMOKE'] = $token
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Write($stdin)
        $p.StandardInput.Close()
        $o = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        @{ Code = $p.ExitCode; Out = $o }
    } -ArgumentList $Rcu, $CtlHome, $script:Token, (($CliArgs | ForEach-Object { Quote-Arg $_ }) -join ' '), $StdinText

    $id = $null
    for ($i = 0; $i -lt 150 -and -not $id; $i++) {
        $m = [regex]::Matches($script:nodeLog.ToString(), '\[approval ([0-9a-f]+)\] [a-z.]+ \(')
        if ($m.Count -gt $before) { $id = $m[$before].Groups[1].Value } else { Start-Sleep -Milliseconds 100 }
    }
    if (-not $id) { Fail "node never asked about: $($CliArgs -join ' ')" }
    $script:nodeProc.StandardInput.WriteLine("$answer $id")
    $script:nodeProc.StandardInput.Flush()
    $null = Wait-Job $job -Timeout 60
    $res = Receive-Job $job
    Remove-Job $job -Force
    if (-not $res) { Fail "controller did not finish: $($CliArgs -join ' ')" }
    return $res
}

$port = ([System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0))
$port.Start(); $portNum = $port.LocalEndpoint.Port; $port.Stop()
$Addr = "127.0.0.1:$portNum"
$Hostname = Join-Path $env:SystemRoot 'System32\hostname.exe'
$Cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'

Write-Host "`n== rcu init"
$r = Run-Rcu $NodeHome @('init')
if ($r.Code -ne 0 -or $r.Out -notmatch '"created":true') { Fail "init: $($r.Out) $($r.Err)" }
$r = Run-Rcu $NodeHome @('init')
if ($r.Out -notmatch '"created":false') { Fail "second init must not overwrite: $($r.Out)" }

Write-Host "`n== write policy"
@"
[node]
name = "smoke-node"
[capabilities]
exec = true
fs_read = true
fs_write = true
[fs]
roots = ['$Work']
[approval]
ui = "terminal"
[[exec.allow]]
program = '$Hostname'
args = ["**"]
risk = "read"
"@ | Set-Content -Path (Join-Path $NodeHome 'policy.toml') -Encoding UTF8
$r = Run-Rcu $NodeHome @('policy-check')
if ($r.Code -ne 0 -or $r.Out -notmatch '"ok":true') { Fail "policy-check: $($r.Out) $($r.Err)" }

Write-Host "`n== start node on $Addr"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Rcu
$psi.Arguments = "serve --bind $Addr"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.EnvironmentVariables['RCU_HOME'] = $NodeHome
$script:nodeProc = [System.Diagnostics.Process]::Start($psi)
$sb = $script:nodeLog
$handler = { if ($EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) } }
$null = Register-ObjectEvent -InputObject $script:nodeProc -EventName OutputDataReceived -Action $handler -MessageData $sb
$null = Register-ObjectEvent -InputObject $script:nodeProc -EventName ErrorDataReceived -Action $handler -MessageData $sb
$script:nodeProc.BeginOutputReadLine()
$script:nodeProc.BeginErrorReadLine()

$code = $null
for ($i = 0; $i -lt 100 -and -not $code; $i++) {
    $m = [regex]::Match($script:nodeLog.ToString(), 'pairing code \(5 min\): ([A-Z0-9]+)')
    if ($m.Success) { $code = $m.Groups[1].Value } else { Start-Sleep -Milliseconds 100 }
}
if (-not $code) { Fail 'node never printed a pairing code' }
Start-Sleep -Milliseconds 300

Write-Host "`n== pair"
$r = Run-Rcu $CtlHome @('pair', 'smoke', $Addr, $code, '--print-token')
if ($r.Code -ne 0) { Fail "pair: $($r.Out) $($r.Err)" }
$script:Token = ($r.Out | ConvertFrom-Json).token
if (-not $script:Token) { Fail 'no token' }

Write-Host "`n== info"
$r = Run-Rcu $CtlHome @('info', 'smoke')
if ($r.Code -ne 0 -or $r.Out -notmatch 'fs.write') { Fail "info: $($r.Out) $($r.Err)" }

Write-Host "`n== exec through approval"
$r = Approved 'y' @('exec', 'smoke', '--', $Hostname)
if ($r.Code -ne 0) { Fail "exec exit $($r.Code): $($r.Out)" }
if (($r.Out | ConvertFrom-Json).stdout.Trim().Length -eq 0) { Fail "exec printed nothing: $($r.Out)" }

Write-Host "`n== denied approval"
$r = Approved 'n' @('exec', 'smoke', '--', $Hostname)
if ($r.Code -ne 2) { Fail "denied exec must exit 2, got $($r.Code): $($r.Out)" }

Write-Host "`n== write then read"
$target = Join-Path $Work 'new.txt'
$r = Approved 'y' @('write', 'smoke', $target) 'written by smoke'
if ($r.Code -ne 0) { Fail "write exit $($r.Code): $($r.Out)" }
if ((Get-Content $target -Raw).Trim() -ne 'written by smoke') { Fail 'file content on node' }
$r = Approved 'y' @('read', 'smoke', $target)
if ($r.Code -ne 0 -or ($r.Out | ConvertFrom-Json).text.Trim() -ne 'written by smoke') { Fail "read back: $($r.Out)" }

Write-Host "`n== policy denials never ask"
$r = Run-Rcu $CtlHome @('exec', 'smoke', '--', $Cmd, '/c', 'echo hi')
if ($r.Code -ne 2) { Fail "cmd.exe must be denied with exit 2, got $($r.Code): $($r.Out)" }
$r = Run-Rcu $CtlHome @('read', 'smoke', (Join-Path $NodeHome 'policy.toml'))
if ($r.Code -ne 2) { Fail "path outside roots must exit 2, got $($r.Code): $($r.Out)" }
# NTFS alternate data stream and DOS device names must not slip through
foreach ($bad in @("$target`:stream", (Join-Path $Work 'CON'), (Join-Path $Work 'x.txt.'))) {
    $r = Run-Rcu $CtlHome @('read', 'smoke', $bad)
    if ($r.Code -eq 0) { Fail "suspicious path was readable: $bad" }
}

Write-Host "`n== revoke"
$r = Run-Rcu $NodeHome @('revoke', '--all')
if ($r.Out -notmatch '"revoked":1') { Fail "revoke: $($r.Out)" }
$r = Run-Rcu $CtlHome @('info', 'smoke')
if ($r.Code -ne 4) { Fail "revoked token must exit 4, got $($r.Code): $($r.Out)" }

$script:nodeProc.Kill()
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
$ver = (& $Rcu --version)
Write-Host "`nSMOKE OK ($ver)"
