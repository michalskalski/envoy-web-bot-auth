use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{collections::BTreeSet, net::IpAddr};
use url::Url;

#[derive(Clone, Debug)]
pub struct DestinationPolicy {
    allowed_ports: BTreeSet<u16>,
}

impl DestinationPolicy {
    pub fn new(allowed_ports: impl IntoIterator<Item = u16>) -> Result<Self, &'static str> {
        let allowed_ports = allowed_ports.into_iter().collect::<BTreeSet<_>>();
        if allowed_ports.is_empty() || allowed_ports.contains(&0) {
            return Err("allowed ports must contain at least one non-zero port");
        }
        if allowed_ports.len() > 64 {
            return Err("allowed ports must contain at most 64 unique ports");
        }
        Ok(Self { allowed_ports })
    }

    pub fn validate_url(&self, url: &Url) -> Result<(), &'static str> {
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !self
                .allowed_ports
                .contains(&url.port_or_known_default().unwrap_or(0))
        {
            return Err("unsafe_destination");
        }
        Ok(())
    }
}

impl Default for DestinationPolicy {
    fn default() -> Self {
        Self::new([443]).expect("the default destination port is valid")
    }
}

/// Reject a DNS answer when any address is unsafe.
/// This blocks mixed answers from steering address selection.
pub(super) fn validate_all_addresses(addresses: &[IpAddr]) -> Result<Vec<IpAddr>, &'static str> {
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !globally_reachable(*address))
    {
        return Err("unsafe_address");
    }
    let mut unique = addresses.to_vec();
    unique.sort_unstable();
    unique.dedup();
    Ok(unique)
}

fn globally_reachable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => !IPV4_NOT_GLOBAL
            .iter()
            .any(|prefix| IpNet::V4(*prefix).contains(&IpAddr::V4(address))),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return globally_reachable(IpAddr::V4(mapped));
            }
            if IPV6_GLOBAL_EXCEPTIONS
                .iter()
                .any(|prefix| IpNet::V6(*prefix).contains(&IpAddr::V6(address)))
            {
                return true;
            }
            !IPV6_NOT_GLOBAL
                .iter()
                .any(|prefix| IpNet::V6(*prefix).contains(&IpAddr::V6(address)))
        }
    }
}

// IANA IPv4 data pinned on 2025-10-09.
// Public exceptions stay outside these deny ranges.
static IPV4_NOT_GLOBAL: std::sync::LazyLock<Vec<Ipv4Net>> = std::sync::LazyLock::new(|| {
    [
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("100.64.0.0", 10),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.0.0.0", 29),
        ("192.0.0.8", 32),
        ("192.0.0.11", 32),
        ("192.0.0.12", 30),
        ("192.0.0.16", 28),
        ("192.0.0.32", 27),
        ("192.0.0.64", 26),
        ("192.0.0.128", 26),
        ("192.0.0.192", 27),
        ("192.0.0.224", 28),
        ("192.0.0.240", 29),
        ("192.0.0.248", 30),
        ("192.0.0.252", 31),
        ("192.0.0.254", 32),
        ("192.0.0.255", 32),
        ("192.0.2.0", 24),
        ("192.88.99.0", 24),
        ("192.168.0.0", 16),
        ("198.18.0.0", 15),
        ("198.51.100.0", 24),
        ("203.0.113.0", 24),
        ("224.0.0.0", 4),
        ("240.0.0.0", 4),
    ]
    .into_iter()
    .map(|(address, prefix)| Ipv4Net::new(address.parse().unwrap(), prefix).unwrap())
    .collect()
});

// IANA IPv6 data pinned on 2025-10-09.
static IPV6_NOT_GLOBAL: std::sync::LazyLock<Vec<Ipv6Net>> = std::sync::LazyLock::new(|| {
    [
        ("::", 128),
        ("::1", 128),
        // Deprecated IPv4 compatibility addresses are not a safe egress form.
        ("::", 96),
        ("64:ff9b:1::", 48),
        ("100::", 64),
        ("100:0:0:1::", 64),
        ("2001::", 23),
        ("2001:db8::", 32),
        ("2002::", 16),
        ("3fff::", 20),
        ("5f00::", 16),
        ("fc00::", 7),
        ("fe80::", 10),
        ("ff00::", 8),
    ]
    .into_iter()
    .map(|(address, prefix)| Ipv6Net::new(address.parse().unwrap(), prefix).unwrap())
    .collect()
});

static IPV6_GLOBAL_EXCEPTIONS: std::sync::LazyLock<Vec<Ipv6Net>> = std::sync::LazyLock::new(|| {
    [
        ("2001:1::1", 128),
        ("2001:1::2", 128),
        ("2001:1::3", 128),
        ("2001:3::", 32),
        ("2001:4:112::", 48),
        ("2001:20::", 28),
        ("2001:30::", 28),
    ]
    .into_iter()
    .map(|(address, prefix)| Ipv6Net::new(address.parse().unwrap(), prefix).unwrap())
    .collect()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_special_purpose_ranges_are_rejected() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::",
            "::1",
            "::8.8.8.8",
            "::192.0.2.1",
            "::ffff:127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001:2::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
        ] {
            assert!(
                validate_all_addresses(&[address.parse().unwrap()]).is_err(),
                "{address}"
            );
        }
        assert!(validate_all_addresses(&["8.8.8.8".parse().unwrap()]).is_ok());
        assert!(validate_all_addresses(&["2606:4700:4700::1111".parse().unwrap()]).is_ok());
        for address in [
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
        ] {
            assert!(
                validate_all_addresses(&[address.parse().unwrap()]).is_ok(),
                "{address}"
            );
        }
    }

    #[test]
    fn every_pinned_range_rejects_its_boundaries() {
        for prefix in IPV4_NOT_GLOBAL.iter() {
            assert!(!globally_reachable(IpAddr::V4(prefix.network())));
            assert!(!globally_reachable(IpAddr::V4(prefix.broadcast())));
        }
        for prefix in IPV6_NOT_GLOBAL.iter() {
            let first = prefix.network();
            let suffix_bits = 128 - prefix.prefix_len();
            let last = std::net::Ipv6Addr::from(u128::from(first) | ((1u128 << suffix_bits) - 1));
            assert!(!globally_reachable(IpAddr::V6(first)));
            assert!(!globally_reachable(IpAddr::V6(last)));
        }
    }

    #[test]
    fn mixed_dns_answers_are_rejected() {
        assert!(
            validate_all_addresses(&["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()])
                .is_err()
        );
    }

    #[test]
    fn target_ports_are_explicit() {
        let default = DestinationPolicy::default();
        assert!(
            default
                .validate_url(&Url::parse("https://example.com/").unwrap())
                .is_ok()
        );
        assert!(
            default
                .validate_url(&Url::parse("https://example.com:8443/").unwrap())
                .is_err()
        );
    }
}
