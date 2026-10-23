#![cfg(unix)]

use rcu::exec;
use std::time::Duration;

fn tool(c: &[&str]) -> Option<String> {
    c.iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}

#[cfg(target_os = "linux")]
fn any_process_with_arg(needle: &str) -> bool {
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .any(|c| String::from_utf8_lossy(&c).contains(needle))
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_kills_the_whole_process_group() {
    let (Some(find), Some(sleep)) = (
        tool(&["/usr/bin/find", "/bin/find"]),
        tool(&["/usr/bin/sleep", "/bin/sleep"]),
    ) else {
        return;
    };
    // find 가 손자 프로세스 sleep 을 띄운다(같은 프로세스 그룹). 제한 시간 뒤 둘 다 사라져야 한다.
    let marker = "7123.25";
    let args: Vec<String> = ["/tmp", "-maxdepth", "0", "-exec", &sleep, marker, ";"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let out = exec::run(&find, &args, Duration::from_millis(500), 1024).unwrap();
    assert!(out.timed_out);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !any_process_with_arg(marker),
        "grandchild survived the timeout"
    );
}

#[test]
fn too_many_concurrent_commands_are_refused() {
    let Some(sleep) = tool(&["/usr/bin/sleep", "/bin/sleep"]) else {
        return;
    };
    let handles: Vec<_> = (0..exec::MAX_CONCURRENT + 4)
        .map(|_| {
            let sleep = sleep.clone();
            std::thread::spawn(move || {
                exec::run(&sleep, &["1".into()], Duration::from_secs(5), 1024)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let busy = results
        .iter()
        .filter(|r| matches!(r, Err(e) if e.code == "BUSY"))
        .count();
    let ok = results.iter().filter(|r| r.is_ok()).count();
    assert!(busy >= 1, "at least one request must be refused");
    assert!(ok >= exec::MAX_CONCURRENT.min(results.len()) - 1);
    // 끝난 뒤에는 자리가 비워진다.
    assert!(exec::run(&sleep, &["0".into()], Duration::from_secs(5), 1024).is_ok());
}
