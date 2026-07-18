// SPDX-License-Identifier: Apache-2.0
use std::{ops::Deref, ptr};

/// Zero a mutable byte slice using `write_volatile` to prevent the
/// compiler from eliminating the writes as dead stores.
///
/// # Safety
/// The caller must ensure the slice points to initialized memory that
/// is about to be deallocated or will not be read again as valid data.
pub(crate) unsafe fn clear_memory(buf: &mut [u8]) {
    for i in 0..buf.len() {
        // SAFETY: The caller guarantees the slice points to initialized
        // memory that is about to be dropped or deallocated.
        unsafe { ptr::write_volatile(buf.as_mut_ptr().add(i), 0) };
    }
}

pub(crate) struct MemoryGuard(Vec<u8>);

pub(crate) struct PasswordBuf {
    guard: MemoryGuard,
}

impl PasswordBuf {
    pub(crate) fn new(s: &str) -> Result<Self, std::io::Error> {
        let mut guard = MemoryGuard::new(s.len())?;
        guard.as_mut_slice().copy_from_slice(s.as_bytes());
        Ok(Self { guard })
    }
}

impl Deref for PasswordBuf {
    type Target = str;

    fn deref(&self) -> &str {
        let bytes = self.guard.as_slice();
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }
}

unsafe impl Send for MemoryGuard {}
unsafe impl Send for PasswordBuf {}

impl MemoryGuard {
    pub(crate) fn new(size: usize) -> Result<Self, std::io::Error> {
        if size == 0 {
            return Ok(MemoryGuard(Vec::new()));
        }
        let v = vec![0u8; size];
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(std::io::Error::other("sysconf(_SC_PAGESIZE) failed"));
        }
        let page_size = page_size as usize;
        let base = v.as_ptr() as usize;
        let aligned = base & !(page_size - 1);
        let end = base + size;
        let aligned_len = end.next_multiple_of(page_size) - aligned;

        let ret =
            unsafe { libc::mlock(aligned as *const libc::c_void, aligned_len) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ret = unsafe {
            libc::madvise(
                aligned as *mut libc::c_void,
                aligned_len,
                libc::MADV_DONTDUMP,
            )
        };
        if ret != 0 {
            unsafe {
                libc::munlock(aligned as *const libc::c_void, aligned_len)
            };
            return Err(std::io::Error::last_os_error());
        }
        Ok(MemoryGuard(v))
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        let len = self.0.len();
        if len == 0 {
            return;
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            // Best-effort zero without munlock.
            unsafe { clear_memory(&mut self.0) };
            return;
        }
        let page_size = page_size as usize;
        let base = self.0.as_ptr() as usize;
        let aligned = base & !(page_size - 1);
        let end = base + len;
        let aligned_len = end.next_multiple_of(page_size) - aligned;

        // Use write_volatile rather than fill(0): the compiler may
        // eliminate fill(0) as a dead store when the allocation is
        // about to be freed (see Vec docs: "Even if you zero a Vec's
        // memory first, that might not actually happen because the
        // optimizer does not consider this a side-effect").
        unsafe { clear_memory(&mut self.0) };
        unsafe {
            libc::munlock(aligned as *const libc::c_void, aligned_len);
        }
    }
}
