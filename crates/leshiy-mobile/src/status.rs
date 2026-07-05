/// Connection state exposed to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// A status snapshot pushed to the UI (~1 Hz).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Status {
    pub state: ConnState,
    pub up_bytes: u64,
    pub down_bytes: u64,
}

/// The state to publish once the initial dial resolves. The mobile path runs `TunEngine`
/// directly (not the supervisor `Machine`), so connection state is lifecycle-driven here
/// rather than mapped from `leshiy_client::State`.
pub fn next_on_dial_result(ok: bool) -> ConnState {
    if ok {
        ConnState::Connected
    } else {
        ConnState::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_ok_is_connected() {
        assert_eq!(next_on_dial_result(true), ConnState::Connected);
    }

    #[test]
    fn dial_err_is_failed() {
        assert_eq!(next_on_dial_result(false), ConnState::Failed);
    }
}
