//! Rights-derived seccomp syscall allowlists — NOT in the TCB.
//!
//! Mirrors the WASM sandbox host-import mapping: the rights bitmask in the
//! capability proof determines which syscalls a tool subprocess may invoke.
//! Linux-only enforcement; Windows/macOS callers use subprocess isolation only.
//!
//! Used by the Python `SeccompExecutor` via duplicated constants (keep in sync)
//! and by future Rust subprocess wrappers.

use crate::tcb::types::{
    Rights, RIGHT_NETWORK, RIGHT_READ, RIGHT_SPAWN, RIGHT_WRITE,
};

/// x86_64 syscall numbers blocked for all profiles (includes execve).
pub const SYSCALL_EXECVE_X86_64: i64 = 59;
pub const SYSCALL_SOCKET_X86_64: i64 = 41;

/// Minimal syscalls every isolated tool needs (memory, exit, basic fd I/O metadata).
const BASE_X86_64: &[i64] = &[
    0,   // read
    1,   // write
    3,   // close
    4,   // stat
    5,   // fstat
    6,   // lstat
    8,   // lseek
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    12,  // brk
    21,  // access
    39,  // getpid
    60,  // exit
    63,  // uname
    72,  // fcntl
    73,  // flock
    78,  // gettimeofday
    79,  // getcwd
    107, // sysinfo
    217, // getdents64
    228, // clock_gettime
    231, // exit_group
    257, // openat
    262, // newfstatat
];

/// Derive an x86_64 seccomp allowlist from the same rights bitmask used by WASM host imports.
pub fn allowlist_for_rights_x86_64(rights: Rights) -> Vec<i64> {
    let mut list: Vec<i64> = BASE_X86_64.to_vec();

    if rights & RIGHT_READ != 0 || rights & RIGHT_WRITE != 0 {
        list.extend([2]); // open — file I/O
    }

    if rights & RIGHT_NETWORK != 0 {
        list.extend([
            SYSCALL_SOCKET_X86_64,
            42,  // connect
            43,  // accept
            44,  // sendto
            45,  // recvfrom
            46,  // sendmsg
            47,  // recvmsg
            49,  // bind
            50,  // listen
            51,  // getsockname
            52,  // getpeername
            54,  // getsockopt
            55,  // setsockopt
        ]);
    }

    if rights & RIGHT_SPAWN != 0 {
        list.extend([
            56,  // clone
            57,  // fork
            SYSCALL_EXECVE_X86_64,
        ]);
    }

    // RIGHT_WRITE alone does not grant execve; RIGHT_EXECUTE is not a separate spawn bit here.
    let _ = RIGHT_WRITE; // explicit: write rights do not add execve

    list.sort_unstable();
    list.dedup();
    list
}

/// True when `nr` is permitted for the given rights on x86_64.
pub fn syscall_permitted_x86_64(rights: Rights, nr: i64) -> bool {
    allowlist_for_rights_x86_64(rights).binary_search(&nr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcb::types::RIGHT_READ;

    #[test]
    fn read_only_profile_blocks_execve_and_socket() {
        let list = allowlist_for_rights_x86_64(RIGHT_READ);
        assert!(
            !list.contains(&SYSCALL_EXECVE_X86_64),
            "execve must not be in read-only allowlist"
        );
        assert!(
            !list.contains(&SYSCALL_SOCKET_X86_64),
            "socket must not be in read-only allowlist"
        );
    }

    #[test]
    fn network_right_adds_socket_not_execve() {
        let list = allowlist_for_rights_x86_64(RIGHT_READ | RIGHT_NETWORK);
        assert!(list.contains(&SYSCALL_SOCKET_X86_64));
        assert!(!list.contains(&SYSCALL_EXECVE_X86_64));
    }

    #[test]
    fn spawn_right_adds_execve() {
        let list = allowlist_for_rights_x86_64(RIGHT_READ | RIGHT_SPAWN);
        assert!(list.contains(&SYSCALL_EXECVE_X86_64));
    }

    #[test]
    fn syscall_permitted_matches_allowlist() {
        let rights = RIGHT_READ;
        assert!(!syscall_permitted_x86_64(rights, SYSCALL_EXECVE_X86_64));
        assert!(syscall_permitted_x86_64(rights, 0)); // read
    }
}
