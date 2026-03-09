//! Page table entry permissions and memory types

/// Memory type for page table entries
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MemoryType {
    /// Normal memory (cacheable, speculative access allowed)
    #[default]
    Normal,
    /// Device memory (non-cacheable, no speculation, strictly ordered)
    Device,
    /// Normal non-cacheable memory (write-combining, suitable for framebuffers)
    ///
    /// This allows write-combining and reordering but bypasses the cache.
    /// Ideal for framebuffers where you want efficient burst writes without
    /// cache pollution or explicit cache maintenance.
    NormalNonCacheable,
}

/// Page table entry permissions
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtePermissions {
    /// Read permission (always true for valid entries)
    pub read: bool,
    /// Write permission
    pub write: bool,
    /// Execute permission
    pub execute: bool,
    /// User-accessible (EL0) permission
    pub user: bool,
    /// Copy-on-Write flag (software-defined, uses reserved bit)
    pub cow: bool,
    /// Global mapping (shared across all ASIDs)
    /// When true (nG=0), the TLB entry is global (kernel mappings)
    /// When false (nG=1), the TLB entry is per-ASID (user mappings)
    pub global: bool,
}

impl PtePermissions {
    /// No permissions (invalid)
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
        user: false,
        cow: false,
        global: false,
    };

    /// Create read-only permissions
    /// Kernel mappings are global (user=false -> global=true)
    /// User mappings are per-ASID (user=true -> global=false)
    #[inline]
    pub const fn ro(user: bool) -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
            user,
            cow: false,
            global: !user,
        }
    }

    /// Create read-write permissions
    /// Kernel mappings are global (user=false -> global=true)
    /// User mappings are per-ASID (user=true -> global=false)
    #[inline]
    pub const fn rw(user: bool) -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            user,
            cow: false,
            global: !user,
        }
    }

    /// Create read-execute permissions
    /// Kernel mappings are global (user=false -> global=true)
    /// User mappings are per-ASID (user=true -> global=false)
    #[inline]
    pub const fn rx(user: bool) -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
            user,
            cow: false,
            global: !user,
        }
    }

    /// Create read-write-execute permissions
    /// Kernel mappings are global (user=false -> global=true)
    /// User mappings are per-ASID (user=true -> global=false)
    #[inline]
    pub const fn rwx(user: bool) -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            user,
            cow: false,
            global: !user,
        }
    }

    /// Mark as copy-on-write
    ///
    /// This converts a writable page to read-only with COW flag set.
    /// When a write fault occurs, the OS can detect this and copy the page.
    #[inline]
    pub const fn into_cow(self) -> Self {
        debug_assert!(self.write);
        Self {
            read: self.read,
            write: false, // Downgrade to read-only
            execute: self.execute,
            user: self.user,
            cow: true,
            global: self.global,
        }
    }

    /// Resolve copy-on-write
    ///
    /// After copying the page, restore write permission and clear COW flag.
    #[inline]
    pub const fn from_cow(self) -> Self {
        debug_assert!(self.cow);
        Self {
            read: self.read,
            write: true, // Restore write permission
            execute: self.execute,
            user: self.user,
            cow: false,
            global: self.global,
        }
    }

    /// Check if this represents kernel-only access
    #[inline]
    pub const fn is_kernel_only(&self) -> bool {
        !self.user
    }

    /// Check if this is writable
    #[inline]
    pub const fn is_writable(&self) -> bool {
        self.write
    }

    /// Check if this is executable
    #[inline]
    pub const fn is_executable(&self) -> bool {
        self.execute
    }

    /// Check if this is copy-on-write
    #[inline]
    pub const fn is_cow(&self) -> bool {
        self.cow
    }

    /// Check if this is a global mapping (shared across all ASIDs)
    #[inline]
    pub const fn is_global(&self) -> bool {
        self.global
    }
}

impl Default for PtePermissions {
    fn default() -> Self {
        Self::NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_ro_kernel() {
        let p = PtePermissions::ro(false);
        assert!(p.read);
        assert!(!p.write);
        assert!(!p.execute);
        assert!(!p.user);
        assert!(!p.cow);
        assert!(p.global);
    }

    #[test_case]
    fn test_ro_user() {
        let p = PtePermissions::ro(true);
        assert!(p.read);
        assert!(!p.write);
        assert!(!p.execute);
        assert!(p.user);
        assert!(!p.cow);
        assert!(!p.global);
    }

    #[test_case]
    fn test_rw_kernel() {
        let p = PtePermissions::rw(false);
        assert!(p.read);
        assert!(p.write);
        assert!(!p.execute);
        assert!(!p.user);
        assert!(p.global);
    }

    #[test_case]
    fn test_rw_user() {
        let p = PtePermissions::rw(true);
        assert!(p.write);
        assert!(!p.execute);
        assert!(p.user);
        assert!(!p.global);
    }

    #[test_case]
    fn test_rx_kernel() {
        let p = PtePermissions::rx(false);
        assert!(!p.write);
        assert!(p.execute);
        assert!(!p.user);
        assert!(p.global);
    }

    #[test_case]
    fn test_rx_user() {
        let p = PtePermissions::rx(true);
        assert!(!p.write);
        assert!(p.execute);
        assert!(p.user);
        assert!(!p.global);
    }

    #[test_case]
    fn test_rwx_kernel() {
        let p = PtePermissions::rwx(false);
        assert!(p.write);
        assert!(p.execute);
        assert!(!p.user);
        assert!(p.global);
    }

    #[test_case]
    fn test_rwx_user() {
        let p = PtePermissions::rwx(true);
        assert!(p.write);
        assert!(p.execute);
        assert!(p.user);
        assert!(!p.global);
    }

    #[test_case]
    fn test_into_cow() {
        let p = PtePermissions::rw(false).into_cow();
        assert!(p.cow);
        assert!(!p.write);
        assert!(p.read);
    }

    #[test_case]
    fn test_from_cow() {
        let p = PtePermissions::rw(false).into_cow().from_cow();
        assert!(!p.cow);
        assert!(p.write);
    }

    #[test_case]
    fn test_is_kernel_only() {
        assert!(PtePermissions::rw(false).is_kernel_only());
        assert!(!PtePermissions::rw(true).is_kernel_only());
    }

    #[test_case]
    fn test_none() {
        let p = PtePermissions::NONE;
        assert!(!p.read);
        assert!(!p.write);
        assert!(!p.execute);
        assert!(!p.user);
        assert!(!p.cow);
        assert!(!p.global);
    }

    #[test_case]
    fn test_global_mirrors_user() {
        // Kernel mappings are global (nG=0), user mappings are per-ASID (nG=1)
        assert!(PtePermissions::ro(false).global);
        assert!(!PtePermissions::ro(true).global);
        assert!(PtePermissions::rwx(false).global);
        assert!(!PtePermissions::rwx(true).global);
    }

    #[test_case]
    fn test_helper_predicates() {
        assert!(PtePermissions::rw(false).is_writable());
        assert!(!PtePermissions::ro(false).is_writable());
        assert!(PtePermissions::rx(false).is_executable());
        assert!(!PtePermissions::rw(false).is_executable());
        assert!(PtePermissions::rw(false).into_cow().is_cow());
        assert!(!PtePermissions::rw(false).is_cow());
    }
}
