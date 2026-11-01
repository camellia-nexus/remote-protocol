use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointHost {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl EndpointHost {
    pub fn to_host_string(&self) -> String {
        match self {
            Self::Ipv4(ip) => ip.to_string(),
            Self::Ipv6(ip) => format!("[{ip}]"),
            Self::Domain(domain) => domain.clone(),
        }
    }

    #[inline]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::Ipv4(_))
    }

    #[inline]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::Ipv6(_))
    }

    #[inline]
    pub fn is_domain(&self) -> bool {
        matches!(self, Self::Domain(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParsedEndpoint {
    pub host: EndpointHost,
    pub raw_host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EndpointError {
    #[error("Endpoint is empty")]
    Empty,
    #[error("Invalid host: {0}")]
    InvalidHost(String),
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Port {0} out of range (must be 1..=65535)")]
    PortOutOfRange(u32),
    #[error("Port arithmetic overflow/underflow on port {port} with offset {offset}")]
    PortOffsetOverflow { port: u16, offset: i32 },
    #[error("Missing port in endpoint")]
    MissingPort,
    #[error("Invalid IPv6 bracket format: {0}")]
    InvalidIpv6Brackets(String),
}

impl ParsedEndpoint {
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(EndpointError::Empty);
        }

        // Bracketed IPv6: [2001:db8::1] or [2001:db8::1]:8080
        if trimmed.starts_with('[') {
            let close_bracket = trimmed
                .find(']')
                .ok_or_else(|| EndpointError::InvalidIpv6Brackets(trimmed.to_owned()))?;
            let host_part = &trimmed[1..close_bracket];
            let rest = &trimmed[close_bracket + 1..];

            let ipv6 = Ipv6Addr::from_str(host_part)
                .map_err(|_| EndpointError::InvalidHost(host_part.to_owned()))?;

            let raw_host = format!("[{host_part}]");

            if rest.is_empty() {
                return Ok(Self {
                    host: EndpointHost::Ipv6(ipv6),
                    raw_host,
                    port: None,
                });
            }

            if let Some(port_str) = rest.strip_prefix(':') {
                let port = parse_port(port_str)?;
                return Ok(Self {
                    host: EndpointHost::Ipv6(ipv6),
                    raw_host,
                    port: Some(port),
                });
            }

            return Err(EndpointError::InvalidIpv6Brackets(trimmed.to_owned()));
        }

        // Unbracketed check: count colons
        let colon_count = trimmed.chars().filter(|&c| c == ':').count();
        if colon_count > 1 {
            // Multiple colons without brackets -> must be bare IPv6 without port
            let ipv6 = Ipv6Addr::from_str(trimmed)
                .map_err(|_| EndpointError::InvalidHost(trimmed.to_owned()))?;
            return Ok(Self {
                host: EndpointHost::Ipv6(ipv6),
                raw_host: format!("[{trimmed}]"),
                port: None,
            });
        }

        if colon_count == 1 {
            let (host_str, port_str) = trimmed.split_once(':').unwrap();
            let port = parse_port(port_str)?;
            let host = parse_host_no_colon(host_str)?;
            return Ok(Self {
                raw_host: host_str.to_owned(),
                host,
                port: Some(port),
            });
        }

        // No colons -> bare IPv4 or domain
        let host = parse_host_no_colon(trimmed)?;
        Ok(Self {
            raw_host: trimmed.to_owned(),
            host,
            port: None,
        })
    }

    pub fn to_endpoint_string(&self, default_port: u16) -> Result<String, EndpointError> {
        let port = self.port.unwrap_or(default_port);
        if port == 0 {
            return Err(EndpointError::PortOutOfRange(0));
        }
        Ok(format!("{}:{}", self.raw_host, port))
    }
}

pub fn parse_port(port_str: &str) -> Result<u16, EndpointError> {
    if port_str.is_empty() || !port_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(EndpointError::InvalidPort(port_str.to_owned()));
    }
    let port_num: u32 = port_str
        .parse()
        .map_err(|_| EndpointError::InvalidPort(port_str.to_owned()))?;
    if port_num == 0 || port_num > 65535 {
        return Err(EndpointError::PortOutOfRange(port_num));
    }
    Ok(port_num as u16)
}

fn parse_host_no_colon(host_str: &str) -> Result<EndpointHost, EndpointError> {
    if host_str.is_empty() {
        return Err(EndpointError::InvalidHost(host_str.to_owned()));
    }
    // If it's valid IPv4
    if let Ok(ipv4) = Ipv4Addr::from_str(host_str) {
        return Ok(EndpointHost::Ipv4(ipv4));
    }
    // If it's all digits and dots, but failed Ipv4Addr parse, it's malformed IPv4, not a domain
    if host_str.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(EndpointError::InvalidHost(host_str.to_owned()));
    }
    // Check if valid hostname / domain
    if is_valid_hostname(host_str) {
        return Ok(EndpointHost::Domain(host_str.to_owned()));
    }
    Err(EndpointError::InvalidHost(host_str.to_owned()))
}

/// Validates a hostname label (RFC 1123).
pub fn is_valid_hostname_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    let first = label.chars().next().unwrap();
    let last = label.chars().last().unwrap();
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return false;
    }
    label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Validates a hostname or FQDN (RFC 1123).
pub fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    // Cannot be purely numeric
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    labels.iter().all(|l| is_valid_hostname_label(l))
}

/// Validates a domain name with TLD per RFC 1123 / IANA.
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for (i, label) in labels.iter().enumerate() {
        if !is_valid_hostname_label(label) {
            return false;
        }
        // Last label (TLD) must have at least 2 characters and be alphabetic (or IDN 'xn--')
        if i == labels.len() - 1 {
            if label.len() < 2 {
                return false;
            }
            if !label.chars().all(|c| c.is_ascii_alphabetic()) && !label.starts_with("xn--") {
                return false;
            }
        }
    }
    true
}

#[inline]
pub fn is_ipv4_str(id: &str) -> bool {
    match ParsedEndpoint::parse(id) {
        Ok(ep) => matches!(ep.host, EndpointHost::Ipv4(_)),
        Err(_) => false,
    }
}

#[inline]
pub fn is_ipv6_str(id: &str) -> bool {
    match ParsedEndpoint::parse(id) {
        Ok(ep) => matches!(ep.host, EndpointHost::Ipv6(_)),
        Err(_) => false,
    }
}

#[inline]
pub fn is_ip_str(id: &str) -> bool {
    match ParsedEndpoint::parse(id) {
        Ok(ep) => matches!(ep.host, EndpointHost::Ipv4(_) | EndpointHost::Ipv6(_)),
        Err(_) => false,
    }
}

#[inline]
pub fn is_domain_port_str(id: &str) -> bool {
    match ParsedEndpoint::parse(id) {
        Ok(ep) => {
            matches!(ep.host, EndpointHost::Domain(ref d) if is_valid_domain(d))
                && ep.port.is_some()
        }
        Err(_) => false,
    }
}
