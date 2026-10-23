use base64::Engine;
use rcu::desktop::*;

fn args(cmd: &std::process::Command) -> Vec<String> {
    cmd.get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

fn env(cmd: &std::process::Command, key: &str) -> Option<String> {
    cmd.get_envs()
        .find(|(k, _)| k.to_string_lossy() == key)
        .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
}

#[test]
fn combos_parse_and_reject() {
    let c = parse_combo("Ctrl+Shift+T").unwrap();
    assert_eq!(c.modifiers, vec![Modifier::Ctrl, Modifier::Shift]);
    assert_eq!(c.key, KeyName::Char('t'));
    assert_eq!(c.display(), "ctrl+shift+t");
    assert_eq!(
        parse_combo("cmd+space").unwrap().key,
        KeyName::Named("space")
    );
    assert_eq!(parse_combo("enter").unwrap().modifiers, vec![]);
    assert_eq!(parse_combo("F5").unwrap().key, KeyName::Named("f5"));
    for bad in [
        "",
        "ctrl+",
        "ctrl+ctrl+a",
        "hyper+a",
        "ctrl+f13",
        "ab",
        "ctrl+;",
        "a+b",
        "ctrl+{ENTER}",
    ] {
        assert!(parse_combo(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn typed_text_rules() {
    assert!(check_typed_text("hello\nworld\t!", 500).is_ok());
    assert!(check_typed_text("", 500).is_err());
    assert!(check_typed_text(&"a".repeat(501), 500).is_err());
    assert!(check_typed_text("bell\x07", 500).is_err());
    assert!(check_typed_text("esc\x1b[2J", 500).is_err());
    assert!(check_typed_text("한글 ✓", 500).is_ok());
}

#[test]
fn png_header_parsing() {
    assert_eq!(png_size(TINY_PNG), Some((1, 1)));
    assert_eq!(png_size(b"not a png at all, just text bytes"), None);
    assert_eq!(png_size(&[]), None);
    let mut truncated = TINY_PNG[..20].to_vec();
    assert_eq!(png_size(&truncated), None);
    truncated.clear();
}

#[test]
fn sendkeys_escaping() {
    assert_eq!(sendkeys_escape("a+b"), "a{+}b");
    assert_eq!(sendkeys_escape("^%~(){}[]"), "{^}{%}{~}{(}{)}{{}{}}{[}{]}");
    assert_eq!(sendkeys_escape("hi\r\nthere\tx"), "hi{ENTER}there{TAB}x");
    assert_eq!(sendkeys_escape("plain 한글"), "plain 한글");
}

#[test]
fn sendkeys_combos() {
    let f = |s| sendkeys_combo(&parse_combo(s).unwrap());
    assert_eq!(f("ctrl+c").as_deref(), Some("^c"));
    assert_eq!(f("ctrl+shift+t").as_deref(), Some("^+t"));
    assert_eq!(f("alt+f4").as_deref(), Some("%{F4}"));
    assert_eq!(f("enter").as_deref(), Some("{ENTER}"));
    assert_eq!(f("pagedown").as_deref(), Some("{PGDN}"));
    assert_eq!(f("win+r"), None);
}

#[test]
fn windows_commands_carry_request_data_in_env_only() {
    let evil = "'; Remove-Item -Recurse C:\\ ; '";
    let cmd = windows_keys_command(&sendkeys_escape(evil));
    assert!(args(&cmd).iter().all(|a| !a.contains("Remove-Item")));
    assert!(env(&cmd, "RCU_KEYS").unwrap().contains("Remove-Item"));

    let click = windows_click_command(10, -20, Button::Right);
    assert_eq!(env(&click, "RCU_X").as_deref(), Some("10"));
    assert_eq!(env(&click, "RCU_Y").as_deref(), Some("-20"));
    assert_eq!(env(&click, "RCU_BUTTON").as_deref(), Some("right"));

    let cap = windows_capture_command(1280);
    assert_eq!(env(&cap, "RCU_MAX_WIDTH").as_deref(), Some("1280"));
}

#[test]
fn windows_capture_output_parses() {
    let b64 = base64::engine::general_purpose::STANDARD.encode(TINY_PNG);
    let cap = parse_windows_capture(&format!("2560 1440 {b64}\r\n")).unwrap();
    assert_eq!((cap.screen_width, cap.screen_height), (2560, 1440));
    assert_eq!(cap.png, TINY_PNG);
    assert!(parse_windows_capture("2560 1440").is_none());
    assert!(parse_windows_capture("a b c").is_none());
    let junk = base64::engine::general_purpose::STANDARD.encode(b"not a png");
    assert!(parse_windows_capture(&format!("1 1 {junk}")).is_none());
}

#[test]
fn mac_type_and_click_pass_data_after_the_argv_separator() {
    let evil = "\"; do shell script \"id\" -- ";
    let cmd = mac_type_command(evil);
    let a = args(&cmd);
    let sep = a.iter().position(|x| x == "--").unwrap();
    assert_eq!(a[sep + 1], evil);
    assert!(a[..sep].iter().all(|x| !x.contains("do shell script")));

    let click = mac_click_command(100, 200, Button::Left, false).unwrap();
    let a = args(&click);
    let sep = a.iter().position(|x| x == "--").unwrap();
    assert_eq!(&a[sep + 1..], ["100", "200"]);

    assert!(mac_click_command(1, 2, Button::Right, false).is_none());
    let cli = mac_click_command(1, 2, Button::Right, true).unwrap();
    assert_eq!(args(&cli), vec!["rc:1,2"]);
}

#[test]
fn mac_key_commands() {
    let key = |s| mac_key_command(&parse_combo(s).unwrap()).map(|c| args(&c).join(" "));
    let k = key("cmd+shift+4").unwrap();
    assert!(
        k.contains("keystroke (item 1 of argv) using {shift down, command down}")
            || k.contains("using {command down, shift down}")
    );
    assert!(k.ends_with("-- 4"));
    assert!(key("enter").unwrap().contains("key code 36"));
    assert!(key("ctrl+left")
        .unwrap()
        .contains("key code 123 using {control down}"));
    assert!(key("f12").unwrap().contains("key code 111"));
}

#[test]
fn mac_bounds_parse() {
    assert_eq!(parse_mac_bounds("0, 0, 1512, 982\n"), Some((1512, 982)));
    assert_eq!(parse_mac_bounds("0, 0, 0, 0"), None);
    assert_eq!(parse_mac_bounds("nonsense"), None);
}

#[test]
fn fake_desktop_records_calls() {
    let d = FakeDesktop::default();
    let cap = d.capture(1280).unwrap();
    assert_eq!(png_size(&cap.png), Some((1, 1)));
    d.click(5, 6, Button::Left).unwrap();
    d.type_text("héllo").unwrap();
    d.key(&parse_combo("ctrl+c").unwrap()).unwrap();
    assert_eq!(
        *d.calls.lock().unwrap(),
        vec![
            "capture max_width=1280",
            "click 5,6 left",
            "type 5 chars",
            "key ctrl+c"
        ]
    );
}
