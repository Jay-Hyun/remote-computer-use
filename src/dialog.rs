//! 승인을 OS 대화상자로 받는다(맥 osascript, 윈도우 MessageBox, 리눅스 zenity).
//! 터미널 프롬프트와 함께 동작하고, 먼저 온 답이 이긴다.
//!
//! 요청 설명은 명령줄이 아니라 인자·환경 변수로 넘겨 스크립트 주입을 막는다.

use crate::approval::{Decision, Gate, PendingInfo};
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Windows,
    Linux,
}

pub fn current() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOs
    } else if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub title: String,
    pub body: String,
    /// 기간 승인 버튼을 보일지(destructive·external 은 보이지 않는다)
    pub allow_grant: bool,
    pub grant_minutes: u64,
}

pub fn prompt_for(info: &PendingInfo, grant_minutes: u64) -> Prompt {
    Prompt {
        title: "rcu: approve request?".to_string(),
        body: format!(
            "{} ({})\n\n{}",
            info.capability,
            info.risk.as_str(),
            info.summary
        ),
        allow_grant: !info.risk.always_needs_approval(),
        grant_minutes,
    }
}

fn once_label() -> &'static str {
    "Allow once"
}

fn grant_label(p: &Prompt) -> String {
    format!("Allow {} min", p.grant_minutes)
}

/// 이 OS 에서 대화상자를 띄울 수 있는지.
pub fn available() -> bool {
    match current() {
        Platform::MacOs | Platform::Windows => true,
        Platform::Linux => {
            let has_display = std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some();
            has_display && which("zenity")
        }
    }
}

fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
        .unwrap_or(false)
}

/// 윈도우 승인 창(고정 스크립트). 결과는 `once` / `grant` / `deny` 중 하나를 출력한다.
const PS_APPROVAL_FORM: &str = "\
Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
$f = New-Object System.Windows.Forms.Form; $f.Tag = 'deny'; \
$f.Text = $env:RCU_PROMPT_TITLE; $f.TopMost = $true; $f.StartPosition = 'CenterScreen'; \
$f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; \
$f.ClientSize = New-Object System.Drawing.Size(620, 300); \
$t = New-Object System.Windows.Forms.TextBox; $t.Multiline = $true; $t.ReadOnly = $true; \
$t.ScrollBars = 'Vertical'; $t.Text = $env:RCU_PROMPT_BODY; \
$t.Location = New-Object System.Drawing.Point(12, 12); $t.Size = New-Object System.Drawing.Size(596, 230); \
$f.Controls.Add($t); \
function New-Btn($text, $x, $val) { \
  $b = New-Object System.Windows.Forms.Button; $b.Text = $text; $b.Tag = $val; \
  $b.Size = New-Object System.Drawing.Size(190, 36); $b.Location = New-Object System.Drawing.Point($x, 252); \
  $b.Add_Click({ param($s, $e) $form = $s.FindForm(); $form.Tag = $s.Tag; $form.Close() }); \
  $f.Controls.Add($b); return $b }; \
$deny = New-Btn 'Deny' 12 'deny'; \
$once = New-Btn $env:RCU_LABEL_ONCE 215 'once'; \
if ($env:RCU_ALLOW_GRANT -eq '1') { $grant = New-Btn $env:RCU_LABEL_GRANT 418 'grant' }; \
$f.AcceptButton = $deny; $f.CancelButton = $deny; \
$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 290000; \
$timer.Add_Tick({ $f.Close() }); $timer.Start(); \
[void]$f.ShowDialog(); Write-Output $f.Tag";

pub fn build_command(platform: Platform, p: &Prompt) -> Command {
    match platform {
        Platform::MacOs => {
            let buttons = if p.allow_grant {
                format!("{{\"Deny\", \"{}\", \"{}\"}}", once_label(), grant_label(p))
            } else {
                format!("{{\"Deny\", \"{}\"}}", once_label())
            };
            let mut cmd = Command::new("osascript");
            cmd.args([
                "-e",
                "on run argv",
                "-e",
                &format!(
                    "display dialog (item 1 of argv) with title (item 2 of argv) buttons {buttons} \
                     default button \"Deny\" cancel button \"Deny\" with icon caution giving up after 290"
                ),
                "-e",
                "end run",
                "--",
                &p.body,
                &p.title,
            ]);
            cmd
        }
        Platform::Windows => {
            // 버튼에 이름을 붙인 작은 창. (MessageBox 의 예/아니오/취소는 "아니오"를 거부로 읽는 사람이
            // 기간 승인을 누르게 만든다.) 요청 설명은 환경 변수로만 전달하고 스크립트에는 넣지 않는다.
            let mut cmd = Command::new("powershell");
            cmd.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                PS_APPROVAL_FORM,
            ])
            .env("RCU_PROMPT_BODY", &p.body)
            .env("RCU_PROMPT_TITLE", &p.title)
            .env("RCU_LABEL_ONCE", once_label())
            .env("RCU_LABEL_GRANT", grant_label(p))
            .env("RCU_ALLOW_GRANT", if p.allow_grant { "1" } else { "0" });
            cmd
        }
        Platform::Linux => {
            // zenity 는 --text 에 g_strcompress 를 적용해 `\n` 을 줄바꿈으로 바꾼다. 백슬래시를 두 배로 해서
            // 요청 속 `\n` 이 가짜 줄을 만들지 못하게 한다.
            let body = p.body.replace('\\', "\\\\");
            let mut cmd = Command::new("zenity");
            cmd.args([
                "--question",
                "--no-markup",
                "--timeout",
                "290",
                "--title",
                &p.title,
                "--text",
                &body,
                "--ok-label",
                once_label(),
                "--cancel-label",
                "Deny",
            ]);
            if p.allow_grant {
                cmd.args(["--extra-button", &grant_label(p)]);
            }
            cmd
        }
    }
}

/// 대화상자 프로세스의 종료 결과를 결정으로 바꾼다. 애매하면 거부.
pub fn parse_outcome(platform: Platform, p: &Prompt, success: bool, stdout: &str) -> Decision {
    let out = stdout.trim();
    match platform {
        Platform::MacOs => {
            if !success || out.contains("gave up:true") {
                Decision::Deny
            } else if p.allow_grant && out.contains(&format!("button returned:{}", grant_label(p)))
            {
                Decision::Grant
            } else if out.contains(&format!("button returned:{}", once_label())) {
                Decision::Once
            } else {
                Decision::Deny
            }
        }
        Platform::Windows => match out {
            "once" => Decision::Once,
            "grant" if p.allow_grant => Decision::Grant,
            _ => Decision::Deny,
        },
        Platform::Linux => {
            if success {
                Decision::Once
            } else if p.allow_grant && out == grant_label(p) {
                Decision::Grant
            } else {
                Decision::Deny
            }
        }
    }
}

/// 대화상자를 띄우고 답을 기다린다. `still_waiting` 이 false 가 되면(터미널 등에서
/// 먼저 답함) 대화상자를 닫고 None. 띄우지 못하면 None.
pub fn show(
    info: &PendingInfo,
    grant_minutes: u64,
    still_waiting: &dyn Fn() -> bool,
) -> Option<Decision> {
    let platform = current();
    let prompt = prompt_for(info, grant_minutes);
    let mut child = build_command(platform, &prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_string(&mut out);
                }
                return Some(parse_outcome(platform, &prompt, status.success(), &out));
            }
            Ok(None) => {
                if !still_waiting() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
            Err(_) => return None,
        }
    }
}

pub type Runner = Arc<dyn Fn(&PendingInfo, &dyn Fn() -> bool) -> Option<Decision> + Send + Sync>;

/// 새 승인 요청마다 호출: 별도 스레드에서 대화상자를 띄우고 답을 게이트에 전한다.
/// 답이 어느 쪽에서 왔는지 알리려고 `on_resolved(info, decision)` 을 부른다.
pub fn spawn_prompt(
    gate: Arc<Gate>,
    info: PendingInfo,
    runner: Runner,
    on_resolved: impl Fn(&PendingInfo, Decision) + Send + 'static,
) {
    std::thread::spawn(move || {
        let id = info.id.clone();
        let g = gate.clone();
        let still_waiting = move || g.waiting().iter().any(|p| p.id == id);
        if let Some(decision) = runner(&info, &still_waiting) {
            if gate.resolve(Some(&info.id), decision).is_some() {
                on_resolved(&info, decision);
            }
        }
    });
}
