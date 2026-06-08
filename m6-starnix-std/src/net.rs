//! Network types
//!
//! Pure data types for IP addresses — no OS networking.
//! Starnix uses these for socket address representations.

/// An IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Addr([u8; 4]);

impl Ipv4Addr {
    pub const LOCALHOST: Self = Self([127, 0, 0, 1]);
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    pub const fn octets(&self) -> [u8; 4] {
        self.0
    }

    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    pub const fn is_unspecified(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    pub fn from_bits(bits: u32) -> Self {
        Self(bits.to_be_bytes())
    }

    pub fn to_bits(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}

impl core::fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// An IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Addr([u8; 16]);

impl Ipv6Addr {
    pub const LOCALHOST: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pub const UNSPECIFIED: Self = Self([0; 16]);

    #[allow(clippy::too_many_arguments)]
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        let [a1, a2] = a.to_be_bytes();
        let [b1, b2] = b.to_be_bytes();
        let [c1, c2] = c.to_be_bytes();
        let [d1, d2] = d.to_be_bytes();
        let [e1, e2] = e.to_be_bytes();
        let [f1, f2] = f.to_be_bytes();
        let [g1, g2] = g.to_be_bytes();
        let [h1, h2] = h.to_be_bytes();
        Self([
            a1, a2, b1, b2, c1, c2, d1, d2, e1, e2, f1, f2, g1, g2, h1, h2,
        ])
    }

    pub const fn octets(&self) -> [u8; 16] {
        self.0
    }

    pub const fn segments(&self) -> [u16; 8] {
        [
            u16::from_be_bytes([self.0[0], self.0[1]]),
            u16::from_be_bytes([self.0[2], self.0[3]]),
            u16::from_be_bytes([self.0[4], self.0[5]]),
            u16::from_be_bytes([self.0[6], self.0[7]]),
            u16::from_be_bytes([self.0[8], self.0[9]]),
            u16::from_be_bytes([self.0[10], self.0[11]]),
            u16::from_be_bytes([self.0[12], self.0[13]]),
            u16::from_be_bytes([self.0[14], self.0[15]]),
        ]
    }

    pub const fn is_loopback(&self) -> bool {
        let s = self.segments();
        s[0] == 0
            && s[1] == 0
            && s[2] == 0
            && s[3] == 0
            && s[4] == 0
            && s[5] == 0
            && s[6] == 0
            && s[7] == 1
    }

    pub const fn is_unspecified(&self) -> bool {
        let s = self.segments();
        s[0] == 0
            && s[1] == 0
            && s[2] == 0
            && s[3] == 0
            && s[4] == 0
            && s[5] == 0
            && s[6] == 0
            && s[7] == 0
    }
}

impl core::fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let segs = self.segments();
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7]
        )
    }
}

/// An IP address (v4 or v6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl core::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpAddr::V4(v4) => v4.fmt(f),
            IpAddr::V6(v6) => v6.fmt(f),
        }
    }
}

/// A socket address (IP + port).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketAddrV4 {
    ip: Ipv4Addr,
    port: u16,
}

impl SocketAddrV4 {
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }

    pub const fn ip(&self) -> &Ipv4Addr {
        &self.ip
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketAddrV6 {
    ip: Ipv6Addr,
    port: u16,
    flowinfo: u32,
    scope_id: u32,
}

impl SocketAddrV6 {
    pub const fn new(ip: Ipv6Addr, port: u16, flowinfo: u32, scope_id: u32) -> Self {
        Self {
            ip,
            port,
            flowinfo,
            scope_id,
        }
    }

    pub const fn ip(&self) -> &Ipv6Addr {
        &self.ip
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn flowinfo(&self) -> u32 {
        self.flowinfo
    }

    pub const fn scope_id(&self) -> u32 {
        self.scope_id
    }
}
