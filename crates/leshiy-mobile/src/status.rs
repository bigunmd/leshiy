use leshiy_client::State;

/// Connection state exposed to the UI (mirrors `leshiy_client::State`, with `Error` -> `Failed`).
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

/// Pure mapping from the supervisor's `State` to the FFI `ConnState`.
///
/// Tested now; wired into the status poller in Phase 2 when the bridge observes the
/// supervisor's `watch::Receiver<State>` instead of reporting a placeholder.
#[allow(dead_code)]
pub fn map_state(s: State) -> ConnState {
    match s {
        State::Disconnected => ConnState::Disconnected,
        State::Connecting => ConnState::Connecting,
        State::Connected => ConnState::Connected,
        State::Reconnecting => ConnState::Reconnecting,
        State::Error => ConnState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_connected() {
        assert_eq!(map_state(State::Connected), ConnState::Connected);
    }

    #[test]
    fn maps_disconnected() {
        assert_eq!(map_state(State::Disconnected), ConnState::Disconnected);
    }

    #[test]
    fn maps_error_to_failed() {
        assert_eq!(map_state(State::Error), ConnState::Failed);
    }
}
