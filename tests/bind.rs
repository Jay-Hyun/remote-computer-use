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
