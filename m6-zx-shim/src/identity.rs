//! Kernel object identity types (Koid, Name, ObjectType)

/// Maximum length of a kernel object name, including the trailing NUL.
pub const ZX_MAX_NAME_LEN: usize = 32;

/// A kernel object identifier — a globally unique, non-reusable u64.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Koid(u64);

impl Koid {
    /// Builds a `Koid` from its raw value.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw u64 identifier.
    pub const fn raw_koid(&self) -> u64 {
        self.0
    }
}

/// A fixed-size kernel object name (NUL-padded, at most `ZX_MAX_NAME_LEN - 1`
/// significant bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Name([u8; ZX_MAX_NAME_LEN]);

impl Name {
    /// An empty name.
    pub const EMPTY: Self = Self([0u8; ZX_MAX_NAME_LEN]);

    /// Builds a name from raw bytes, truncating to fit and dropping any bytes
    /// at or after the first NUL.
    pub const fn from_bytes_lossy(b: &[u8]) -> Self {
        let mut inner = [0u8; ZX_MAX_NAME_LEN];
        let limit = ZX_MAX_NAME_LEN - 1;
        let mut i = 0;
        while i < b.len() && i < limit {
            let byte = b[i];
            if byte == 0 {
                break;
            }
            inner[i] = byte;
            i += 1;
        }
        Self(inner)
    }

    /// Builds a name, truncating the input string to fit.
    pub const fn new_lossy(s: &str) -> Self {
        Self::from_bytes_lossy(s.as_bytes())
    }

    /// Returns the significant bytes of the name (up to the first NUL).
    pub fn as_bytes(&self) -> &[u8] {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        &self.0[..end]
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl core::fmt::Debug for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = core::str::from_utf8(self.as_bytes()).unwrap_or("<invalid>");
        write!(f, "Name({s:?})")
    }
}

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = core::str::from_utf8(self.as_bytes()).unwrap_or("<invalid>");
        f.write_str(s)
    }
}

/// The type of a kernel object.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u32)]
pub enum ObjectType {
    /// No object / unknown type.
    #[default]
    None = 0,
    Process = 1,
    Thread = 2,
    Vmo = 3,
    Channel = 4,
    Event = 5,
    Port = 6,
    EventPair = 16,
    Socket = 14,
    Vmar = 18,
    Timer = 22,
    Counter = 30,
    Clock = 25,
}
