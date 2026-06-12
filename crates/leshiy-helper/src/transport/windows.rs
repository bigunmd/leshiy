//! Windows named-pipe transport — the crate's only `unsafe` module (ADR-0029).
//!
//! The UAC-elevated (high-IL) helper creates `\\.\pipe\leshiy-helper` with a security
//! descriptor built from SDDL: a DACL granting GENERIC_ALL only to Local System, Builtin
//! Administrators, and the launching user's SID (`allow.sid`), plus a **medium** mandatory
//! integrity label so the unprivileged (medium-IL) GUI can open it across the UAC boundary.
//! Authorization is OS-enforced by the DACL and additionally checked per-connection by
//! comparing the client's token SID to `allow.sid` (mirroring the Unix `peer_uid` gate).
use crate::runner::VpnRunner;
use crate::server::{Auth, ServeMode, spawn_conn, spawn_exit_watchdog};
use crate::transport::Endpoint;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

const PIPE_BUF: u32 = 64 * 1024;

fn last_err() -> std::io::Error {
    std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// SDDL for the pipe: DACL = SYSTEM + Administrators + the user SID; SACL = medium integrity,
/// no-write-up. See ADR-0029.
fn sddl_for(sid: &str) -> String {
    format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})S:(ML;;NW;;;ME)")
}

/// Create one named-pipe server instance bound to a user-SID security descriptor and wrap it
/// into tokio. `first` must be true for the first instance only (FILE_FLAG_FIRST_PIPE_INSTANCE).
fn create_server(name: &str, first: bool, sid: &str) -> std::io::Result<NamedPipeServer> {
    let wide_name = to_wide(name);
    let wide_sddl = to_wide(&sddl_for(sid));

    // Build the security descriptor from SDDL.
    let mut psd: *mut core::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_err());
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        bInheritHandle: 0,
    };
    let open_mode = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUF,
            PIPE_BUF,
            0,
            &sa,
        )
    };
    // The SD has been copied into the kernel object; free our SDDL-allocated copy.
    unsafe { LocalFree(psd) };

    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(last_err());
    }
    // SAFETY: the handle was created with FILE_FLAG_OVERLAPPED (required by tokio) and is a
    // fresh, owned named-pipe server handle; ownership transfers to the NamedPipeServer.
    // tokio's inherent `from_raw_handle` returns io::Result (it registers with the runtime).
    unsafe { NamedPipeServer::from_raw_handle(handle as _) }
}

/// Read the connected client's user SID as an SDDL string (e.g. "S-1-5-21-…").
fn client_sid(server: &NamedPipeServer) -> std::io::Result<String> {
    let mut pid: u32 = 0;
    if unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as _, &mut pid) } == 0 {
        return Err(last_err());
    }
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc.is_null() {
        return Err(last_err());
    }
    let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(proc, TOKEN_QUERY, &mut token) };
    unsafe { CloseHandle(proc) };
    if opened == 0 {
        return Err(last_err());
    }

    // Two-call pattern: query the required buffer size, then the TOKEN_USER.
    let mut len: u32 = 0;
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    let mut buf = vec![0u8; len.max(1) as usize];
    let got =
        unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut _, len, &mut len) };
    unsafe { CloseHandle(token) };
    if got == 0 {
        return Err(last_err());
    }

    let token_user = buf.as_ptr() as *const TOKEN_USER;
    let sid_ptr = unsafe { (*token_user).User.Sid };
    let mut str_sid: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid_ptr, &mut str_sid) } == 0 {
        return Err(last_err());
    }
    // Read the NUL-terminated wide string, then free it.
    let mut s = String::new();
    let mut p = str_sid;
    unsafe {
        while *p != 0 {
            s.push(char::from_u32(*p as u32).unwrap_or('\u{fffd}'));
            p = p.add(1);
        }
        LocalFree(str_sid as *mut _);
    }
    Ok(s)
}

/// Serve the control channel over a named pipe authorized to `allow.sid`. Fails closed if no
/// SID was supplied. Each accepted connection's client SID is re-checked (defense-in-depth).
pub async fn serve(
    endpoint: &Endpoint,
    runner: Arc<dyn VpnRunner>,
    allow: Auth,
    mode: ServeMode,
) -> std::io::Result<()> {
    let Endpoint::Pipe(name) = endpoint;
    let sid = allow.sid.clone().ok_or_else(|| {
        std::io::Error::other("missing --allow-sid: refusing to serve an unauthenticated pipe")
    })?;

    let exit = Arc::new(tokio::sync::Notify::new());
    if matches!(mode, ServeMode::Ephemeral) {
        spawn_exit_watchdog(runner.clone(), exit.clone());
    }
    let mut first = true;
    loop {
        // One pending pipe instance; spawn the handler on connect so a held-open Subscribe
        // doesn't block concurrent Stop. The exit arm lets an ephemeral helper exit when the
        // session ends (watchdog) or the GUI's control stream drops (spawn_conn).
        let server = create_server(name, first, &sid)?;
        first = false;
        tokio::select! {
            res = server.connect() => {
                res?;
                // Defense-in-depth: silently drop a connection whose client SID isn't allowed.
                if matches!(client_sid(&server), Ok(got) if got.eq_ignore_ascii_case(&sid)) {
                    spawn_conn(server, runner.clone(), mode, exit.clone());
                } else {
                    drop(server); // no reply (no oracle)
                }
            }
            _ = exit.notified() => return Ok(()),
        }
    }
}

/// Connect a client to the named pipe, retrying briefly while the server is busy creating the
/// next instance (`ERROR_PIPE_BUSY` = 231).
pub async fn connect(name: &str) -> std::io::Result<NamedPipeClient> {
    loop {
        match ClientOptions::new().open(name) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(231) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}
