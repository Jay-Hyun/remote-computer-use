//! 화면 캡처와 입력(M5). 능력 `screen`, `input` 이 꺼져 있으면 호출되지 않는다.
//!
//! 맥·윈도우 백엔드는 OS 기본 도구(osascript, screencapture, PowerShell)를 부른다. 요청 텍스트는 스크립트
//! 본문이 아니라 인자·환경 변수로만 넘기고, 명령 생성과 결과 해석은 순수 함수로 분리해 시험한다.
//! 캡처는 디스크에 남기지 않는다(맥은 임시 파일이 필요해 0700 디렉터리에 만들어 읽자마자 지운다).

use crate::dialog::{current, Platform};
use crate::ops::OpError;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
}

impl Button {
    pub fn parse(s: &str) -> Option<Button> {
        match s {
            "left" => Some(Button::Left),
            "right" => Some(Button::Right),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Button::Left => "left",
            Button::Right => "right",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Capture {
    pub png: Vec<u8>,
    /// 화면의 논리 크기. 클릭 좌표는 이 좌표계를 쓴다(이미지는 더 작을 수 있다).
    pub screen_width: u32,
    pub screen_height: u32,
}

pub trait Desktop: Send + Sync {
    fn capture(&self, max_width: u32) -> Result<Capture, OpError>;
    fn click(&self, x: i32, y: i32, button: Button) -> Result<(), OpError>;
    fn type_text(&self, text: &str) -> Result<(), OpError>;
    fn key(&self, combo: &Combo) -> Result<(), OpError>;
}

// ---- 키 조합 ----------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Ctrl,
    Alt,
    Shift,
    /// 맥 command / 윈도우 키
    Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyName {
    Char(char),
    Named(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combo {
    pub modifiers: Vec<Modifier>,
    pub key: KeyName,
}

const NAMED_KEYS: &[&str] = &[
    "enter",
    "tab",
    "escape",
    "space",
    "backspace",
    "delete",
    "up",
    "down",
    "left",
    "right",
    "home",
    "end",
    "pageup",
    "pagedown",
    "f1",
    "f2",
    "f3",
    "f4",
    "f5",
    "f6",
    "f7",
    "f8",
    "f9",
    "f10",
    "f11",
    "f12",
];

/// `ctrl+shift+t`, `cmd+space`, `enter` 같은 조합. 허용 목록 밖은 거부한다.
pub fn parse_combo(text: &str) -> Result<Combo, String> {
    let lower = text.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return Err("empty key combination".into());
    }
    let parts: Vec<&str> = lower.split('+').collect();
    let (key_part, mods) = parts.split_last().ok_or("empty key combination")?;
    let mut modifiers = Vec::new();
    for m in mods {
        let modifier = match *m {
            "ctrl" | "control" => Modifier::Ctrl,
            "alt" | "option" => Modifier::Alt,
            "shift" => Modifier::Shift,
            "cmd" | "command" | "win" | "meta" | "super" => Modifier::Meta,
            _ => return Err(format!("unknown modifier: {m}")),
        };
        if modifiers.contains(&modifier) {
            return Err("duplicate modifier".into());
        }
        modifiers.push(modifier);
    }
    let key = if let Some(name) = NAMED_KEYS.iter().find(|n| **n == *key_part) {
        KeyName::Named(name)
    } else {
        let mut chars = key_part.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) if c.is_ascii_alphanumeric() => KeyName::Char(c),
            _ => return Err(format!("unknown key: {key_part}")),
        }
    };
    Ok(Combo { modifiers, key })
}

impl Combo {
    /// 승인 창에 보일 이름.
    pub fn display(&self) -> String {
        let mut parts: Vec<String> = self
            .modifiers
            .iter()
            .map(|m| {
                match m {
                    Modifier::Ctrl => "ctrl",
                    Modifier::Alt => "alt",
                    Modifier::Shift => "shift",
                    Modifier::Meta => "cmd/win",
                }
                .to_string()
            })
            .collect();
        parts.push(match &self.key {
            KeyName::Char(c) => c.to_string(),
            KeyName::Named(n) => n.to_string(),
        });
        parts.join("+")
    }
}

// ---- 입력 텍스트 검사 -------------------------------------------------------------------------

/// 타이핑할 텍스트: 줄바꿈·탭 외의 제어 문자는 거부한다.
pub fn check_typed_text(text: &str, max_chars: usize) -> Result<(), &'static str> {
    if text.is_empty() {
        return Err("text is empty");
    }
    if text.chars().count() > max_chars {
        return Err("text is longer than the node's limit");
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err("text contains control characters");
    }
    Ok(())
}

// ---- PNG --------------------------------------------------------------------------------------

/// PNG 헤더에서 (폭, 높이). PNG 가 아니면 None.
pub fn png_size(bytes: &[u8]) -> Option<(u32, u32)> {
    const MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 24 || !bytes.starts_with(MAGIC) || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
    let h = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
    Some((w, h))
}

// ---- 윈도우: SendKeys 이스케이프와 스크립트 -----------------------------------------------------

/// SendKeys 에서 특수한 문자(`+ ^ % ~ ( ) { } [ ]`)를 `{c}` 로 감싸고 줄바꿈·탭을 키 이름으로 바꾼다.
pub fn sendkeys_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '+' | '^' | '%' | '~' | '(' | ')' | '{' | '}' | '[' | ']' => {
                out.push('{');
                out.push(c);
                out.push('}');
            }
            '\r' => {}
            '\n' => out.push_str("{ENTER}"),
            '\t' => out.push_str("{TAB}"),
            c => out.push(c),
        }
    }
    out
}

/// 조합을 SendKeys 문자열로. 윈도우 키는 SendKeys 로 못 보내므로 None.
pub fn sendkeys_combo(combo: &Combo) -> Option<String> {
    let mut out = String::new();
    for m in &combo.modifiers {
        out.push(match m {
            Modifier::Ctrl => '^',
            Modifier::Alt => '%',
            Modifier::Shift => '+',
            Modifier::Meta => return None,
        });
    }
    match &combo.key {
        KeyName::Char(c) => out.push(*c),
        KeyName::Named(n) => out.push_str(match *n {
            "enter" => "{ENTER}",
            "tab" => "{TAB}",
            "escape" => "{ESC}",
            "space" => " ",
            "backspace" => "{BACKSPACE}",
            "delete" => "{DELETE}",
            "up" => "{UP}",
            "down" => "{DOWN}",
            "left" => "{LEFT}",
            "right" => "{RIGHT}",
            "home" => "{HOME}",
            "end" => "{END}",
            "pageup" => "{PGUP}",
            "pagedown" => "{PGDN}",
            f => return Some(format!("{out}{{{}}}", f.to_ascii_uppercase())),
        }),
    }
    Some(out)
}

const PS_CAPTURE: &str = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \
$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; \
$g=[System.Drawing.Graphics]::FromImage($bmp); \
$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); \
$max=[int]$env:RCU_MAX_WIDTH; $out=$bmp; \
if($bmp.Width -gt $max){$h=[int]($bmp.Height*$max/$bmp.Width); $out=New-Object System.Drawing.Bitmap $bmp,$max,$h}; \
$ms=New-Object System.IO.MemoryStream; $out.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png); \
Write-Output ('{0} {1} {2}' -f $b.Width,$b.Height,[Convert]::ToBase64String($ms.ToArray()))";

const PS_CLICK: &str =
    "Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool \
SetCursorPos(int x,int y); [DllImport(\"user32.dll\")] public static extern void \
mouse_event(uint f,uint dx,uint dy,uint d,UIntPtr e);' -Name U -Namespace W; \
[W.U]::SetCursorPos([int]$env:RCU_X,[int]$env:RCU_Y) | Out-Null; \
if($env:RCU_BUTTON -eq 'right'){$d=0x08;$u=0x10}else{$d=0x02;$u=0x04}; \
[W.U]::mouse_event($d,0,0,0,[UIntPtr]::Zero); [W.U]::mouse_event($u,0,0,0,[UIntPtr]::Zero)";

const PS_SENDKEYS: &str =
    "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait($env:RCU_KEYS)";

fn powershell(script: &str) -> Command {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    cmd
}

pub fn windows_capture_command(max_width: u32) -> Command {
    let mut cmd = powershell(PS_CAPTURE);
    cmd.env("RCU_MAX_WIDTH", max_width.to_string());
    cmd
}

pub fn windows_click_command(x: i32, y: i32, button: Button) -> Command {
    let mut cmd = powershell(PS_CLICK);
    cmd.env("RCU_X", x.to_string())
        .env("RCU_Y", y.to_string())
        .env("RCU_BUTTON", button.as_str());
    cmd
}

pub fn windows_keys_command(sendkeys: &str) -> Command {
    let mut cmd = powershell(PS_SENDKEYS);
    cmd.env("RCU_KEYS", sendkeys);
    cmd
}

/// `<폭> <높이> <base64>` 한 줄.
pub fn parse_windows_capture(stdout: &str) -> Option<Capture> {
    use base64::Engine;
    let mut parts = stdout.split_whitespace();
    let (w, h, data) = (parts.next()?, parts.next()?, parts.next()?);
    let png = base64::engine::general_purpose::STANDARD
        .decode(data)
        .ok()?;
    png_size(&png)?;
    Some(Capture {
        png,
        screen_width: w.parse().ok()?,
        screen_height: h.parse().ok()?,
    })
}

// ---- 맥 ---------------------------------------------------------------------------------------

pub fn mac_capture_command(path: &std::path::Path) -> Command {
    let mut cmd = Command::new("screencapture");
    cmd.args(["-x", "-t", "png"]).arg(path);
    cmd
}

pub fn mac_resize_command(path: &std::path::Path, width: u32) -> Command {
    let mut cmd = Command::new("sips");
    cmd.args(["--resampleWidth", &width.to_string()]).arg(path);
    cmd
}

pub fn mac_screen_size_command() -> Command {
    let mut cmd = Command::new("osascript");
    cmd.args([
        "-e",
        "tell application \"Finder\" to get bounds of window of desktop",
    ]);
    cmd
}

/// `0, 0, 1512, 982` → (1512, 982)
pub fn parse_mac_bounds(stdout: &str) -> Option<(u32, u32)> {
    let nums: Vec<i64> = stdout
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    match nums.as_slice() {
        [x0, y0, x1, y1] if x1 > x0 && y1 > y0 => Some(((x1 - x0) as u32, (y1 - y0) as u32)),
        _ => None,
    }
}

pub fn mac_click_command(x: i32, y: i32, button: Button, have_cliclick: bool) -> Option<Command> {
    if have_cliclick {
        let verb = if button == Button::Right { "rc" } else { "c" };
        let mut cmd = Command::new("cliclick");
        cmd.arg(format!("{verb}:{x},{y}"));
        return Some(cmd);
    }
    if button == Button::Right {
        return None;
    }
    let mut cmd = Command::new("osascript");
    cmd.args([
        "-e",
        "on run argv",
        "-e",
        "tell application \"System Events\" to click at {(item 1 of argv) as integer, (item 2 of argv) as integer}",
        "-e",
        "end run",
        "--",
    ])
    .arg(x.to_string())
    .arg(y.to_string());
    Some(cmd)
}

pub fn mac_type_command(text: &str) -> Command {
    let mut cmd = Command::new("osascript");
    cmd.args([
        "-e",
        "on run argv",
        "-e",
        "tell application \"System Events\" to keystroke (item 1 of argv)",
        "-e",
        "end run",
        "--",
        text,
    ]);
    cmd
}

fn mac_key_code(name: &str) -> Option<u32> {
    Some(match name {
        "enter" => 36,
        "tab" => 48,
        "escape" => 53,
        "space" => 49,
        "backspace" => 51,
        "delete" => 117,
        "up" => 126,
        "down" => 125,
        "left" => 123,
        "right" => 124,
        "home" => 115,
        "end" => 119,
        "pageup" => 116,
        "pagedown" => 121,
        "f1" => 122,
        "f2" => 120,
        "f3" => 99,
        "f4" => 118,
        "f5" => 96,
        "f6" => 97,
        "f7" => 98,
        "f8" => 100,
        "f9" => 101,
        "f10" => 109,
        "f11" => 103,
        "f12" => 111,
        _ => return None,
    })
}

pub fn mac_key_command(combo: &Combo) -> Option<Command> {
    let using = if combo.modifiers.is_empty() {
        String::new()
    } else {
        let list: Vec<&str> = combo
            .modifiers
            .iter()
            .map(|m| match m {
                Modifier::Ctrl => "control down",
                Modifier::Alt => "option down",
                Modifier::Shift => "shift down",
                Modifier::Meta => "command down",
            })
            .collect();
        format!(" using {{{}}}", list.join(", "))
    };
    let mut cmd = Command::new("osascript");
    match &combo.key {
        KeyName::Char(c) => {
            cmd.args([
                "-e",
                "on run argv",
                "-e",
                &format!("tell application \"System Events\" to keystroke (item 1 of argv){using}"),
                "-e",
                "end run",
                "--",
            ])
            .arg(c.to_string());
        }
        KeyName::Named(name) => {
            let code = mac_key_code(name)?;
            cmd.args([
                "-e",
                &format!("tell application \"System Events\" to key code {code}{using}"),
            ]);
        }
    }
    Some(cmd)
}

// ---- 실행 도우미 ------------------------------------------------------------------------------

fn failed(code: &'static str) -> OpError {
    OpError::new(
        500,
        code,
        "the desktop tool failed (permissions? no active session?)",
    )
}

pub fn unsupported() -> OpError {
    OpError::new(
        501,
        "UNSUPPORTED",
        "screen and input are not supported on this node's OS",
    )
}

/// 명령을 돌려 (성공 여부, stdout). 제한 시간이 지나면 죽인다.
fn run_tool(
    mut cmd: Command,
    timeout: Duration,
    code: &'static str,
) -> Result<(bool, Vec<u8>), OpError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failed(code))?;
    let mut pipe = child.stdout.take().ok_or_else(|| failed(code))?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failed(code));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return Err(failed(code)),
        }
    };
    let out = reader.join().unwrap_or_default();
    Ok((status.success(), out))
}

const TOOL_TIMEOUT: Duration = Duration::from_secs(20);

fn run_ok(cmd: Command, code: &'static str) -> Result<Vec<u8>, OpError> {
    let (ok, out) = run_tool(cmd, TOOL_TIMEOUT, code)?;
    if ok {
        Ok(out)
    } else {
        Err(failed(code))
    }
}

fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
        .unwrap_or(false)
}

// ---- 실제 백엔드 ------------------------------------------------------------------------------

pub struct SystemDesktop;

impl SystemDesktop {
    fn mac_capture(&self, max_width: u32) -> Result<Capture, OpError> {
        use rand::RngCore;
        let mut rnd = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut rnd);
        let dir = std::env::temp_dir().join(format!(
            "rcu-cap-{}",
            rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|_| failed("SCREEN_FAILED"))?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&dir).map_err(|_| failed("SCREEN_FAILED"))?;

        // 오류가 나도 임시 디렉터리를 지우도록 결과를 모아서 마지막에 정리한다.
        let result = (|| {
            let path = dir.join("screen.png");
            run_ok(mac_capture_command(&path), "SCREEN_FAILED")?;
            let mut png = std::fs::read(&path).map_err(|_| failed("SCREEN_FAILED"))?;
            let (w, _) = png_size(&png).ok_or_else(|| failed("SCREEN_FAILED"))?;
            if w > max_width {
                run_ok(mac_resize_command(&path, max_width), "SCREEN_FAILED")?;
                png = std::fs::read(&path).map_err(|_| failed("SCREEN_FAILED"))?;
            }
            let size = run_ok(mac_screen_size_command(), "SCREEN_FAILED")
                .ok()
                .and_then(|o| parse_mac_bounds(&String::from_utf8_lossy(&o)));
            // 논리 크기를 못 얻으면 이미지 크기를 쓴다(비레티나에서는 같다).
            let (sw, sh) = size
                .or_else(|| png_size(&png))
                .ok_or_else(|| failed("SCREEN_FAILED"))?;
            Ok(Capture {
                png,
                screen_width: sw,
                screen_height: sh,
            })
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}

impl Desktop for SystemDesktop {
    fn capture(&self, max_width: u32) -> Result<Capture, OpError> {
        match current() {
            Platform::MacOs => self.mac_capture(max_width),
            Platform::Windows => {
                let out = run_ok(windows_capture_command(max_width), "SCREEN_FAILED")?;
                parse_windows_capture(&String::from_utf8_lossy(&out))
                    .ok_or_else(|| failed("SCREEN_FAILED"))
            }
            Platform::Linux => Err(unsupported()),
        }
    }

    fn click(&self, x: i32, y: i32, button: Button) -> Result<(), OpError> {
        let cmd = match current() {
            Platform::MacOs => {
                mac_click_command(x, y, button, which("cliclick")).ok_or_else(|| {
                    OpError::new(
                        501,
                        "UNSUPPORTED",
                        "right click on macOS needs `cliclick` installed on the node",
                    )
                })?
            }
            Platform::Windows => windows_click_command(x, y, button),
            Platform::Linux => return Err(unsupported()),
        };
        run_ok(cmd, "INPUT_FAILED").map(|_| ())
    }

    fn type_text(&self, text: &str) -> Result<(), OpError> {
        let cmd = match current() {
            Platform::MacOs => mac_type_command(text),
            Platform::Windows => windows_keys_command(&sendkeys_escape(text)),
            Platform::Linux => return Err(unsupported()),
        };
        run_ok(cmd, "INPUT_FAILED").map(|_| ())
    }

    fn key(&self, combo: &Combo) -> Result<(), OpError> {
        let cmd = match current() {
            Platform::MacOs => mac_key_command(combo).ok_or_else(unsupported)?,
            Platform::Windows => {
                let keys = sendkeys_combo(combo).ok_or_else(|| {
                    OpError::new(
                        501,
                        "UNSUPPORTED",
                        "the Windows key cannot be sent on a Windows node",
                    )
                })?;
                windows_keys_command(&keys)
            }
            Platform::Linux => return Err(unsupported()),
        };
        run_ok(cmd, "INPUT_FAILED").map(|_| ())
    }
}

// ---- 시험용 가짜 ------------------------------------------------------------------------------

/// 호출을 기록하고 작은 PNG 를 돌려준다.
#[derive(Default)]
pub struct FakeDesktop {
    pub calls: std::sync::Mutex<Vec<String>>,
}

/// 1x1 투명 PNG
pub const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xff, 0xff, 0x3f,
    0x00, 0x05, 0xfe, 0x02, 0xfe, 0xa7, 0x35, 0x81, 0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
    0x44, 0xae, 0x42, 0x60, 0x82,
];

impl FakeDesktop {
    fn note(&self, s: String) {
        self.calls.lock().unwrap().push(s);
    }
}

impl Desktop for FakeDesktop {
    fn capture(&self, max_width: u32) -> Result<Capture, OpError> {
        self.note(format!("capture max_width={max_width}"));
        Ok(Capture {
            png: TINY_PNG.to_vec(),
            screen_width: 2560,
            screen_height: 1440,
        })
    }

    fn click(&self, x: i32, y: i32, button: Button) -> Result<(), OpError> {
        self.note(format!("click {x},{y} {}", button.as_str()));
        Ok(())
    }

    fn type_text(&self, text: &str) -> Result<(), OpError> {
        self.note(format!("type {} chars", text.chars().count()));
        Ok(())
    }

    fn key(&self, combo: &Combo) -> Result<(), OpError> {
        self.note(format!("key {}", combo.display()));
        Ok(())
    }
}
