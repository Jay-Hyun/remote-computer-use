use rcu::bind::is_allowed_ip;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn loopback_and_tailnet_are_allowed() {
    for a in [
        "127.0.0.1",
        "::1",
        "100.64.0.1",
        "100.100.100.100",
        "100.127.255.255",
        "fd7a:115c:a1e0::1",
        "fd7a:115c:a1e0:ab12:4843:cd96:6270:1234",
    ] {
        assert!(is_allowed_ip(ip(a)), "{a}");
    }
}

#[test]
fn everything_else_is_denied() {
    for a in [
        "0.0.0.0",
        "::",
        "192.168.0.10",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.0",
        "fd7a:115c:a1e1::1",
        "fe80::1",
        "2001:db8::1",
    ] {
        assert!(!is_allowed_ip(ip(a)), "{a}");
    }
}

#[test]
fn parses_tailscale_ip_output() {
    use rcu::bind::parse_tailscale_ip;
    assert_eq!(
        parse_tailscale_ip("100.101.102.103\n"),
        Some(ip("100.101.102.103"))
    );
    assert_eq!(
        parse_tailscale_ip("\n  100.64.0.7  \n100.64.0.8\n"),
        Some(ip("100.64.0.7"))
    );
    // 허용 대역이 아니거나 이상한 출력은 쓰지 않는다.
    assert_eq!(parse_tailscale_ip("192.168.1.2\n"), None);
    assert_eq!(parse_tailscale_ip("not an ip\n"), None);
    assert_eq!(parse_tailscale_ip(""), None);
    assert_eq!(parse_tailscale_ip("fd7a:115c:a1e0::1\n"), None); // -4 출력만 쓴다
}
