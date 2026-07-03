// Acquire the listening socket from launchd (macOS socket activation) instead
// of binding it ourselves. launchd owns the socket for the lifetime of the job
// configuration, so it survives process restarts: while we're down the kernel
// queues incoming connections in the accept backlog and the next instance
// drains them. An upgrade — flip the profile symlink, `launchctl kickstart -k`
// — therefore drops zero deliveries, which matters here because GitHub does
// NOT automatically redeliver a failed webhook (see README "Operations →
// Failed deliveries"): a connection refused during a plain-bind restart is a
// permanently lost job until someone replays it.
//
// Activation is opt-in and explicit via the LAUNCHD_SOCKET_NAME env var (set
// it in the plist's EnvironmentVariables to the key used in the `Sockets`
// dict). When it's unset the binary binds LISTEN_ADDR itself, as before, so
// `cargo run`, the tests, and non-launchd hosts are unaffected. There is no
// silent fallback: if LAUNCHD_SOCKET_NAME is set and activation fails we refuse
// to start rather than quietly bind a fresh socket and lose the zero-drop
// property.
//
// The whole binary assumes loopback-only ingress behind a TLS proxy
// (invariant 10). With socket activation the bind address lives in the plist,
// not in the process, so we re-enforce that invariant by reading the inherited
// socket's own address via getsockname (std's local_addr) and refusing a
// non-loopback socket unless ALLOW_NON_LOOPBACK_BIND=1 — the machine checks the
// property rather than trusting the plist.

use std::io;
use std::net::SocketAddr;

use tokio::net::TcpListener;

// FromRawFd/RawFd are only referenced by the fd-adoption path, which is macOS
// (real launchd) or test (fabricated loopback fd) only. Gating the import with
// the same predicate keeps a plain Linux release build free of unused-import
// warnings under `-D warnings`.
#[cfg(any(target_os = "macos", test))]
use std::os::unix::io::{FromRawFd, RawFd};

/// The loopback gate (invariant 10), factored out so both the self-bind path
/// (main) and the socket-activation path (`adopt_listener_fd`) enforce it in
/// exactly one place. Pure: the caller reads ALLOW_NON_LOOPBACK_BIND and passes
/// the decision in, so this is trivially testable without touching the
/// environment.
pub(crate) fn check_loopback(addr: &SocketAddr, allow_non_loopback: bool) -> Result<(), String> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if allow_non_loopback {
        eprintln!("warning: serving on non-loopback address {addr} per ALLOW_NON_LOOPBACK_BIND=1");
        return Ok(());
    }
    Err(format!(
        "refusing to serve on {addr}: this binary expects loopback-only ingress behind a TLS \
         reverse proxy (it does no TLS, rate limiting, or IP allowlisting itself). Set \
         ALLOW_NON_LOOPBACK_BIND=1 to override, only when an external network policy guarantees \
         nothing untrusted can reach the listener."
    ))
}

/// How to obtain the listening socket, decided purely from the
/// LAUNCHD_SOCKET_NAME environment variable.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SocketMode {
    /// Adopt the launchd `Sockets` entry with this (non-empty) name.
    Activate(String),
    /// LAUNCHD_SOCKET_NAME is unset: bind LISTEN_ADDR ourselves.
    SelfBind,
}

/// Interpret the LAUNCHD_SOCKET_NAME env var (pass `std::env::var(..)` straight
/// in). Factored out of `main` so the fail-loud contract is unit-testable
/// without binding a socket:
///
/// - unset -> SelfBind (dev, tests, non-launchd hosts);
/// - a non-empty name -> Activate(name);
/// - present-but-empty, or non-UTF-8 -> Err.
///
/// A present value means the operator configured *something*, so an unusable
/// one is a misconfiguration to reject loudly, NOT a silent fall-back to
/// self-binding — a plist typo like an empty `<string/>` would otherwise
/// quietly forfeit zero-drop restarts and let planned restarts drop deliveries
/// with no error.
pub(crate) fn socket_mode(var: Result<String, std::env::VarError>) -> Result<SocketMode, String> {
    match var {
        Ok(name) if !name.is_empty() => Ok(SocketMode::Activate(name)),
        Ok(_) => Err(
            "LAUNCHD_SOCKET_NAME is set but empty. Unset it to bind LISTEN_ADDR \
                      yourself, or set it to the key of the plist's `Sockets` entry."
                .to_string(),
        ),
        Err(std::env::VarError::NotPresent) => Ok(SocketMode::SelfBind),
        Err(std::env::VarError::NotUnicode(_)) => Err(
            "LAUNCHD_SOCKET_NAME is set to a non-UTF-8 value; it must be the plist's \
                 `Sockets` entry key."
                .to_string(),
        ),
    }
}

/// Adopt an already-open listening socket `fd`, re-enforce the loopback gate on
/// the address it is actually bound to, and hand it to tokio. This is the
/// testable heart of socket activation: it needs no launchd, only a live
/// listening descriptor, so it can be exercised with an fd from a loopback
/// listener created in the test.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn adopt_listener_fd(
    fd: RawFd,
    allow_non_loopback: bool,
) -> io::Result<(TcpListener, SocketAddr)> {
    // SAFETY: `fd` is an open listening socket we own — handed over by launchd
    // (which keeps its own reference to the underlying socket), or, in tests, a
    // listener whose fd we released via into_raw_fd. from_raw_fd takes
    // ownership, so the returned listener closes exactly this descriptor on
    // drop and nothing else touches it.
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };

    // getsockname(2), via local_addr, on a socket we did NOT bind: this is what
    // re-enforces the loopback invariant for an inherited socket. It also fails
    // closed on a non-IP socket (e.g. a misconfigured AF_UNIX `Sockets` entry),
    // whose address family std cannot parse into a SocketAddr.
    let local = std_listener.local_addr()?;
    check_loopback(&local, allow_non_loopback).map_err(io::Error::other)?;

    // tokio requires the descriptor be non-blocking before from_std adopts it.
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    Ok((listener, local))
}

/// Call launch_activate_socket for `name` and return the descriptors launchd
/// created for that `Sockets` entry. libSystem is always linked on macOS, so
/// the symbol is reached via inline FFI rather than a crate — the same approach
/// as fs_security's geteuid/ACL bindings.
#[cfg(target_os = "macos")]
fn activate_socket(name: &str) -> io::Result<Vec<RawFd>> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};

    extern "C" {
        // int launch_activate_socket(const char *name, int **fds, size_t *cnt);
        // Returns 0 on success (fds -> malloc'd array of cnt descriptors, owned
        // by the caller) or an errno value (ESRCH: not launchd-managed / socket
        // already activated; ENOENT: no such name in this job's plist).
        fn launch_activate_socket(
            name: *const c_char,
            fds: *mut *mut c_int,
            cnt: *mut usize,
        ) -> c_int;
        fn free(ptr: *mut c_void);
    }

    let cname = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("LAUNCHD_SOCKET_NAME {name:?} contains an interior NUL byte"),
        )
    })?;

    let mut fds: *mut c_int = std::ptr::null_mut();
    let mut cnt: usize = 0;
    // SAFETY: cname is a valid NUL-terminated C string that outlives the call;
    // &mut fds / &mut cnt are valid out-pointers. On success launchd writes a
    // malloc'd array of `cnt` descriptors to `fds`.
    let rc = unsafe { launch_activate_socket(cname.as_ptr(), &mut fds, &mut cnt) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if fds.is_null() || cnt == 0 {
        return Err(io::Error::other(
            "launch_activate_socket reported success but returned no descriptors",
        ));
    }

    // SAFETY: on success launchd wrote `cnt` valid descriptors to the malloc'd
    // array at `fds`. RawFd is a type alias for c_int on unix, so the slice is
    // already &[RawFd]; to_vec copies the descriptors out (no cast needed).
    let out: Vec<RawFd> = unsafe { std::slice::from_raw_parts(fds, cnt) }.to_vec();
    // SAFETY: `fds` was allocated by launchd with malloc; we own it and have
    // copied every descriptor out, so freeing it now leaks nothing and the
    // descriptors stay open.
    unsafe { free(fds as *mut c_void) };
    Ok(out)
}

/// Take the single listening socket launchd created for `name` and turn it into
/// a loopback-checked tokio listener. Refuses anything but exactly one socket:
/// the binary serves a single listener, and a numeric loopback `SockNodeName`
/// yields exactly one, so a count other than one is a plist misconfiguration
/// worth failing loudly on.
#[cfg(target_os = "macos")]
pub(crate) fn listener_from_launchd(
    name: &str,
    allow_non_loopback: bool,
) -> io::Result<(TcpListener, SocketAddr)> {
    use std::os::unix::io::OwnedFd;

    let fds = activate_socket(name).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "launch_activate_socket({name:?}) failed: {e}. Is the process running under \
                 launchd with a `Sockets` entry keyed {name:?}? LAUNCHD_SOCKET_NAME must match \
                 that key exactly."
            ),
        )
    })?;

    if fds.len() != 1 {
        for &fd in &fds {
            // SAFETY: each fd came from launchd and is not adopted anywhere
            // else; wrapping it in an OwnedFd closes it on drop so the error
            // path leaks no descriptors.
            unsafe { drop(OwnedFd::from_raw_fd(fd)) };
        }
        return Err(io::Error::other(format!(
            "expected exactly one activated socket named {name:?}, got {}. Configure a single \
             `Sockets` entry with SockType stream bound to a numeric loopback address (e.g. \
             SockNodeName 127.0.0.1); a hostname resolving to both IPv4 and IPv6 yields two.",
            fds.len()
        )));
    }
    adopt_listener_fd(fds[0], allow_non_loopback)
}

/// launchd exists only on macOS. On any other target, an operator who set
/// LAUNCHD_SOCKET_NAME has misconfigured the deployment; refuse rather than
/// silently ignore it.
#[cfg(not(target_os = "macos"))]
pub(crate) fn listener_from_launchd(
    _name: &str,
    _allow_non_loopback: bool,
) -> io::Result<(TcpListener, SocketAddr)> {
    Err(io::Error::other(
        "LAUNCHD_SOCKET_NAME is set, but launchd socket activation is only supported on macOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Property: check_loopback succeeds exactly when the address is loopback OR
    // the override is set. Deterministic LCG sweep over IPv4 space (same
    // no-dependency style as the WEBHOOK_PATH router sweep in main.rs); it hits
    // 127/8 for roughly 1 in 256 samples plus a large non-loopback majority,
    // exercising both directions of the invariant.
    #[test]
    fn check_loopback_holds_iff_loopback_or_override() {
        let mut lcg: u64 = 0xda7a_1057_c0ff_ee01;
        let mut next = || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (lcg >> 33) as u32
        };
        for _ in 0..8000 {
            let ip = std::net::Ipv4Addr::from(next());
            let addr = SocketAddr::from((ip, 8080));
            for allow in [false, true] {
                let expected = ip.is_loopback() || allow;
                assert_eq!(
                    check_loopback(&addr, allow).is_ok(),
                    expected,
                    "ip={ip} allow={allow}"
                );
            }
        }
    }

    // Concrete anchors, including IPv6, so a regression in the v6 loopback path
    // (::1) or the all-zeros wildcard (::) is caught even though the sweep
    // above is IPv4-only.
    #[test]
    fn check_loopback_named_cases() {
        for s in ["127.0.0.1:8080", "127.9.9.9:1", "[::1]:8080"] {
            let a: SocketAddr = s.parse().unwrap();
            assert!(check_loopback(&a, false).is_ok(), "{s} must pass unforced");
            assert!(check_loopback(&a, true).is_ok(), "{s} must pass forced");
        }
        for s in [
            "0.0.0.0:8080",
            "192.0.2.7:80",
            "[::]:443",
            "[2001:db8::1]:80",
        ] {
            let a: SocketAddr = s.parse().unwrap();
            assert!(check_loopback(&a, false).is_err(), "{s} must be refused");
            assert!(check_loopback(&a, true).is_ok(), "{s} must pass forced");
        }
    }

    #[test]
    fn socket_mode_named_activates() {
        assert_eq!(
            socket_mode(Ok("Listener".to_string())),
            Ok(SocketMode::Activate("Listener".to_string()))
        );
    }

    #[test]
    fn socket_mode_unset_self_binds() {
        // Only a truly-unset variable falls back to self-bind — the dev, test,
        // and non-launchd path.
        assert_eq!(
            socket_mode(Err(std::env::VarError::NotPresent)),
            Ok(SocketMode::SelfBind)
        );
    }

    #[test]
    fn socket_mode_present_but_empty_is_an_error() {
        // Regression: a present-but-empty LAUNCHD_SOCKET_NAME (e.g. a plist typo
        // with an empty <string/>) must fail loud, not silently self-bind and
        // quietly disable zero-drop restarts.
        assert!(socket_mode(Ok(String::new())).is_err());
    }

    #[test]
    fn socket_mode_non_utf8_is_an_error() {
        // A set-but-non-UTF-8 value is likewise a misconfiguration, not "unset".
        use std::os::unix::ffi::OsStringExt;
        let bad = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
        assert!(socket_mode(Err(std::env::VarError::NotUnicode(bad))).is_err());
    }

    // Adopting the fd of a real loopback listener must yield a listener that is
    // (a) bound to the same loopback address and (b) actually accepting — i.e.
    // wired into the tokio reactor, not just a wrapped descriptor.
    #[tokio::test]
    async fn adopt_yields_a_live_loopback_listener() {
        use std::os::unix::io::IntoRawFd;

        let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_l.local_addr().unwrap();
        let fd = std_l.into_raw_fd();

        let (listener, local) = adopt_listener_fd(fd, false).expect("loopback fd must adopt");
        assert_eq!(local, addr);
        assert!(local.ip().is_loopback());

        let connect = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await });
        let _accepted = listener.accept().await.expect("adopted listener accepts");
        connect
            .await
            .unwrap()
            .expect("client connects to adopted listener");
    }

    // A non-IP socket (e.g. an AF_UNIX `Sockets` entry mistyped into the plist)
    // must be rejected: local_addr cannot parse its address family, so we fail
    // closed rather than serve on something that is not a TCP loopback listener.
    #[tokio::test]
    async fn adopt_rejects_non_ip_socket() {
        use std::os::unix::io::IntoRawFd;

        let dir = crate::test_support::tempdir_like::TempDir::new("adopt-unix").unwrap();
        let path = dir.path().join("s");
        let ul = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let fd = ul.into_raw_fd();
        assert!(
            adopt_listener_fd(fd, false).is_err(),
            "an AF_UNIX socket must not be adopted as a TCP listener"
        );
    }

    // macOS-only FFI smoke test: the test binary has no matching `Sockets`
    // entry, so launch_activate_socket must fail (ESRCH/ENOENT) rather than
    // hand back a descriptor. Also proves the libSystem symbol links and the
    // errno-return path is wired up correctly.
    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_activation_errors_without_a_matching_socket() {
        let err = listener_from_launchd("gh-webhook-spool-nonexistent-xyz", false)
            .expect_err("no such launchd socket must error");
        assert!(
            err.to_string().contains("launch_activate_socket"),
            "error should name the failed call, got: {err}"
        );
    }
}
