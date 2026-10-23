//! 노드가 듣거나 컨트롤러가 접속해도 되는 주소: 루프백, 테일스케일 IPv4/IPv6 대역만.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn is_allowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || in_cgnat(v4),
        IpAddr::V6(v6) => v6.is_loopback() || in_tailscale_v6(v6),
    }
}

/// 100.64.0.0/10
fn in_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

/// fd7a:115c:a1e0::/48
fn in_tailscale_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
}

pub fn check_ip(ip: IpAddr) -> anyhow::Result<()> {
    if is_allowed_ip(ip) {
        Ok(())
    } else {
        anyhow::bail!(
            "address {ip} is not loopback or tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48)"
        )
    }
}

/// `tailscale ip -4` 출력에서 첫 IPv4 주소를 꺼낸다. 허용 대역이 아니면 None.
pub fn parse_tailscale_ip(output: &str) -> Option<IpAddr> {
    output
        .lines()
        .filter_map(|line| line.trim().parse::<IpAddr>().ok())
        .find(|ip| matches!(ip, IpAddr::V4(v4) if in_cgnat(*v4)))
}

/// 이 PC 의 테일스케일 IPv4 를 찾는다. CLI 가 없거나 켜져 있지 않으면 None.
pub fn detect_tailnet_ip() -> Option<IpAddr> {
    const CANDIDATES: &[&str] = &[
        "tailscale",
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
        "C:\\Program Files\\Tailscale\\tailscale.exe",
    ];
    for bin in CANDIDATES {
        let Ok(out) = std::process::Command::new(bin)
            .args(["ip", "-4"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        else {
            continue;
        };
        if out.status.success() {
            if let Some(ip) = parse_tailscale_ip(&String::from_utf8_lossy(&out.stdout)) {
                return Some(ip);
            }
        }
    }
    None
}
