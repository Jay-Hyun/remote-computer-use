use rcu::approval::{Decision, Gate, PendingInfo};
use rcu::dialog::{build_command, parse_outcome, prompt_for, spawn_prompt, Platform, Runner};
use rcu::policy::Risk;
use std::sync::Arc;
use std::time::Duration;

fn info(risk: Risk, summary: &str) -> PendingInfo {
    PendingInfo {
        id: "abcd1234".into(),
        capability: "exec".into(),
        risk,
        summary: summary.into(),
    }
}

fn args(cmd: &std::process::Command) -> Vec<String> {
    cmd.get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn destructive_prompts_have_no_grant_button() {
    assert!(prompt_for(&info(Risk::Read, "x"), 60).allow_grant);
    assert!(prompt_for(&info(Risk::Write, "x"), 60).allow_grant);
    assert!(!prompt_for(&info(Risk::Destructive, "x"), 60).allow_grant);
    assert!(!prompt_for(&info(Risk::External, "x"), 60).allow_grant);
}

#[test]
fn request_text_is_never_spliced_into_a_script() {
    // 따옴표·백틱·$()·세미콜론이 든 요청 설명
    let nasty = "run /bin/x \"; do shell script \"id\" ; `id` $(id) '";
    let p = prompt_for(&info(Risk::Read, nasty), 60);

    let mac = build_command(Platform::MacOs, &p);
    let a = args(&mac);
    let dashdash = a.iter().position(|x| x == "--").expect("argv separator");
    assert!(a[dashdash + 1].contains(nasty), "body goes in argv");
    assert!(
        a[..dashdash].iter().all(|x| !x.contains(nasty)),
        "script text must not contain the request"
    );

    let win = build_command(Platform::Windows, &p);
    assert!(args(&win).iter().all(|x| !x.contains(nasty)));
    let env: Vec<_> = win
        .get_envs()
        .filter_map(|(k, v)| {
            Some((
                k.to_string_lossy().into_owned(),
                v?.to_string_lossy().into_owned(),
            ))
        })
        .collect();
    assert!(env
        .iter()
        .any(|(k, v)| k == "RCU_PROMPT_BODY" && v.contains(nasty)));

    let lin = build_command(Platform::Linux, &p);
    assert!(args(&lin).contains(&p.body)); // 별도 인자 하나
}

#[test]
fn mac_buttons_follow_risk() {
    let p = prompt_for(&info(Risk::Read, "x"), 45);
    let script = args(&build_command(Platform::MacOs, &p)).join(" ");
    assert!(script.contains("Allow 45 min") && script.contains("Allow once"));
    let p = prompt_for(&info(Risk::Destructive, "x"), 45);
    let script = args(&build_command(Platform::MacOs, &p)).join(" ");
    assert!(!script.contains("Allow 45 min"));
}

#[test]
fn mac_outcomes() {
    let p = prompt_for(&info(Risk::Read, "x"), 60);
    let o = |ok, out| parse_outcome(Platform::MacOs, &p, ok, out);
    assert_eq!(
        o(true, "button returned:Allow once, gave up:false\n"),
        Decision::Once
    );
    assert_eq!(
        o(true, "button returned:Allow 60 min, gave up:false\n"),
        Decision::Grant
    );
    assert_eq!(
        o(true, "button returned:Deny, gave up:false\n"),
        Decision::Deny
    );
    assert_eq!(o(true, "button returned:, gave up:true\n"), Decision::Deny);
    assert_eq!(o(false, "button returned:Allow once"), Decision::Deny); // 취소(-128)
    assert_eq!(o(true, "garbage"), Decision::Deny);
    // 위험 요청에서는 기간 승인 응답이 와도 한 번으로도 취급하지 않고 거부
    let d = prompt_for(&info(Risk::Destructive, "x"), 60);
    assert_eq!(
        parse_outcome(
            Platform::MacOs,
            &d,
            true,
            "button returned:Allow 60 min, gave up:false"
        ),
        Decision::Deny
    );
}

#[test]
fn windows_outcomes() {
    let p = prompt_for(&info(Risk::Read, "x"), 60);
    let o = |out| parse_outcome(Platform::Windows, &p, true, out);
    assert_eq!(o("once\r\n"), Decision::Once);
    assert_eq!(o("grant\r\n"), Decision::Grant);
    assert_eq!(o("deny\r\n"), Decision::Deny);
    // 예전 MessageBox 응답이나 알 수 없는 출력은 모두 거부
    for junk in ["Yes", "No", "Cancel", "", "once now"] {
        assert_eq!(o(junk), Decision::Deny, "{junk:?}");
    }
    let d = prompt_for(&info(Risk::Destructive, "x"), 60);
    assert_eq!(
        parse_outcome(Platform::Windows, &d, true, "grant"),
        Decision::Deny
    );
    assert_eq!(
        parse_outcome(Platform::Windows, &d, true, "once"),
        Decision::Once
    );
}

#[test]
fn windows_form_has_named_buttons_and_no_request_text_in_the_script() {
    let p = prompt_for(&info(Risk::Read, "run x"), 45);
    let cmd = build_command(Platform::Windows, &p);
    let script = args(&cmd).join(" ");
    assert!(
        script.contains("New-Btn 'Deny'")
            && script.contains("RCU_LABEL_ONCE")
            && script.contains("RCU_LABEL_GRANT")
    );
    assert!(!script.contains("run x"));
    let env = |k: &str| {
        cmd.get_envs()
            .find(|(key, _)| key.to_string_lossy() == k)
            .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
    };
    assert_eq!(env("RCU_ALLOW_GRANT").as_deref(), Some("1"));
    assert_eq!(env("RCU_LABEL_GRANT").as_deref(), Some("Allow 45 min"));
    let d = build_command(
        Platform::Windows,
        &prompt_for(&info(Risk::Destructive, "x"), 45),
    );
    let denv = d
        .get_envs()
        .find(|(k, _)| k.to_string_lossy() == "RCU_ALLOW_GRANT")
        .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()));
    assert_eq!(denv.as_deref(), Some("0"));
}

#[test]
fn linux_outcomes() {
    let p = prompt_for(&info(Risk::Read, "x"), 60);
    assert_eq!(parse_outcome(Platform::Linux, &p, true, ""), Decision::Once);
    assert_eq!(
        parse_outcome(Platform::Linux, &p, false, "Allow 60 min\n"),
        Decision::Grant
    );
    assert_eq!(
        parse_outcome(Platform::Linux, &p, false, ""),
        Decision::Deny
    );
    let d = prompt_for(&info(Risk::Destructive, "x"), 60);
    assert_eq!(
        parse_outcome(Platform::Linux, &d, false, "Allow 60 min"),
        Decision::Deny
    );
}

#[test]
fn prompt_answer_reaches_the_gate_and_cancels_when_answered_elsewhere() {
    let gate = Arc::new(Gate::new(Duration::from_secs(60)));
    let opened = gate
        .open("tok", "exec", Risk::Read, "run /bin/x".into())
        .unwrap();
    let pending = gate.waiting().remove(0);

    let (tx, rx) = std::sync::mpsc::channel();
    let runner: Runner = Arc::new(|_, _| Some(Decision::Once));
    spawn_prompt(gate.clone(), pending, runner, move |i, d| {
        tx.send((i.id.clone(), d)).unwrap();
    });
    let (id, decision) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        (id.as_str(), decision),
        (opened.id.as_str(), Decision::Once)
    );
    assert!(gate.waiting().is_empty());
    assert_eq!(opened.decision_rx.blocking_recv(), Ok(Decision::Once));

    // 다른 곳(터미널)에서 먼저 답하면 still_waiting 이 false 가 되어 대화상자가 닫힌다.
    let opened2 = gate
        .open("tok", "exec", Risk::Read, "run /bin/y".into())
        .unwrap();
    let pending2 = gate.waiting().remove(0);
    let (tx2, rx2) = std::sync::mpsc::channel();
    let runner: Runner = Arc::new(move |_, still_waiting| {
        for _ in 0..200 {
            if !still_waiting() {
                tx2.send("closed").unwrap();
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        tx2.send("never closed").unwrap();
        None
    });
    spawn_prompt(gate.clone(), pending2, runner, |_, _| {
        panic!("must not resolve twice")
    });
    assert!(gate.resolve(None, Decision::Deny).is_some());
    assert_eq!(rx2.recv_timeout(Duration::from_secs(5)).unwrap(), "closed");
    assert_eq!(opened2.decision_rx.blocking_recv(), Ok(Decision::Deny));
}

#[test]
fn zenity_text_cannot_gain_fake_lines_from_backslash_escapes() {
    // zenity 가 --text 를 g_strcompress 하면 `\n` 이 줄바꿈이 된다. 우리는 백슬래시를 두 배로 넘긴다.
    let p = prompt_for(&info(Risk::Read, "run /bin/x \\nread /tmp/x (read)"), 60);
    let a = args(&build_command(Platform::Linux, &p));
    let text = &a[a.iter().position(|x| x == "--text").unwrap() + 1];
    assert!(text.contains("\\\\nread"), "{text:?}");
    assert!(!text.contains("x \\nread"), "{text:?}");
}

#[test]
fn input_prompts_warn_that_input_can_press_other_approval_windows() {
    let mut i = info(Risk::External, "mouse click (1, 2), left button");
    i.capability = "input".into();
    assert!(prompt_for(&i, 60).body.contains("other approval windows"));
    assert!(!prompt_for(&info(Risk::Read, "x"), 60)
        .body
        .contains("approval windows"));
}
