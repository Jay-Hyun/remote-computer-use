#![cfg(any(target_os = "macos", windows))]
//! 실제 OS 도구(화면 캡처, 입력, 승인 대화상자)를 한 번씩 건드려 보고 결과를 출력한다.
//! 사람이 없는 CI 러너에서는 권한·세션이 없어 실패할 수 있으므로 단정하지 않고 보고만 한다.
//! `RCU_REAL_DESKTOP=1 cargo test --test desktop_real -- --nocapture`

use rcu::approval::PendingInfo;
use rcu::desktop::{parse_combo, Button, Desktop, SystemDesktop};
use rcu::dialog::{build_command, current, prompt_for};
use rcu::policy::Risk;
use std::process::Stdio;
use std::time::Duration;

#[test]
fn probe_real_desktop_tools() {
    if std::env::var("RCU_REAL_DESKTOP").is_err() {
        eprintln!("skipped (set RCU_REAL_DESKTOP=1)");
        return;
    }
    let d = SystemDesktop;
    println!(
        "PROBE capture: {:?}",
        d.capture(1280)
            .map(|c| (c.png.len(), c.screen_width, c.screen_height))
            .map_err(|e| e.to_string())
    );
    println!(
        "PROBE key escape: {:?}",
        d.key(&parse_combo("escape").unwrap())
            .map_err(|e| e.to_string())
    );
    println!(
        "PROBE click: {:?}",
        d.click(5, 5, Button::Left).map_err(|e| e.to_string())
    );

    // 승인 대화상자: 스크립트가 문법 오류 없이 시작해 사람을 기다리면 정상(몇 초 뒤 우리가 끈다).
    let info = PendingInfo {
        id: "probe000".into(),
        capability: "exec".into(),
        risk: Risk::Read,
        summary: "run \"/bin/echo\" [\"probe\"]".into(),
    };
    let mut child = build_command(current(), &prompt_for(&info, 60))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("dialog tool must exist");
    std::thread::sleep(Duration::from_secs(4));
    match child.try_wait().unwrap() {
        None => {
            println!("PROBE dialog: running and waiting for a human (script accepted)");
            let _ = child.kill();
            let _ = child.wait();
        }
        Some(status) => {
            let out = child.wait_with_output().unwrap();
            println!(
                "PROBE dialog: exited early with {status}\n  stdout: {}\n  stderr: {}",
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
}
