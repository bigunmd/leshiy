//! Pure supervisor state machine. No I/O — the async shell (Plan 3) drives it.
use std::time::Duration;

/// Observable connection state (mirrors the 4 ConnectButton states; `Reconnecting`
/// is rendered like `Connecting`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

/// Events fed into the machine by the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// User asked to connect.
    Connect,
    /// User asked to disconnect.
    Disconnect,
    /// A dial attempt succeeded.
    DialSucceeded,
    /// A dial attempt failed.
    DialFailed,
    /// The live tunnel dropped unexpectedly.
    TunnelDropped,
    /// A scheduled backoff timer elapsed.
    BackoffElapsed,
}

/// Side effects the shell must perform, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Begin a dial attempt.
    Dial,
    /// Point the system proxy at the local SOCKS port.
    SetProxy,
    /// Clear the system proxy.
    ClearProxy,
    /// Start the metered SOCKS5 listener.
    StartServing,
    /// Stop the metered SOCKS5 listener.
    StopServing,
    /// Schedule a `BackoffElapsed` after this delay.
    ScheduleBackoff(Duration),
    /// Emit a new observable state to subscribers.
    Emit(State),
}

/// Exponential backoff with a cap: `min(base * 2^attempt, max)`.
pub fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let factor = 2u32.saturating_pow(attempt.min(16));
    base.saturating_mul(factor).min(max)
}

/// The pure supervisor machine.
#[derive(Debug)]
pub struct Machine {
    pub state: State,
    kill_switch: bool,
    proxy_set: bool,
    attempt: u32,
    base: Duration,
    max: Duration,
}

impl Machine {
    pub fn new(kill_switch: bool, base: Duration, max: Duration) -> Self {
        Self {
            state: State::Disconnected,
            kill_switch,
            proxy_set: false,
            attempt: 0,
            base,
            max,
        }
    }

    /// Apply one input, mutate internal state, and return the actions to perform.
    pub fn handle(&mut self, input: Input) -> Vec<Action> {
        use Action::*;
        use Input::*;
        use State::*;

        match (self.state, input) {
            // --- start a fresh connection ---
            (Disconnected | Error, Connect) => {
                self.state = Connecting;
                self.attempt = 0;
                vec![Emit(Connecting), Dial]
            }

            // --- initial dial outcome ---
            (Connecting, DialSucceeded) => {
                self.state = Connected;
                let mut a = Vec::new();
                if !self.proxy_set {
                    self.proxy_set = true;
                    a.push(SetProxy);
                }
                a.push(StartServing);
                a.push(Emit(Connected));
                a
            }
            (Connecting, DialFailed) => {
                self.state = Error;
                vec![Emit(Error)]
            }
            (Connecting, Disconnect) => {
                self.state = Disconnected;
                vec![Emit(Disconnected)]
            }

            // --- live connection ---
            (Connected, TunnelDropped) => {
                self.state = Reconnecting;
                self.attempt = 0;
                let mut a = vec![StopServing];
                if !self.kill_switch && self.proxy_set {
                    self.proxy_set = false;
                    a.push(ClearProxy);
                }
                a.push(ScheduleBackoff(backoff_delay(
                    self.attempt,
                    self.base,
                    self.max,
                )));
                a.push(Emit(Reconnecting));
                a
            }
            (Connected, Disconnect) => {
                self.state = Disconnected;
                let mut a = vec![StopServing];
                if self.proxy_set {
                    self.proxy_set = false;
                    a.push(ClearProxy);
                }
                a.push(Emit(Disconnected));
                a
            }

            // --- reconnecting ---
            (Reconnecting, BackoffElapsed) => vec![Dial],
            (Reconnecting, DialSucceeded) => {
                self.state = Connected;
                self.attempt = 0;
                let mut a = Vec::new();
                if !self.proxy_set {
                    self.proxy_set = true;
                    a.push(SetProxy);
                }
                a.push(StartServing);
                a.push(Emit(Connected));
                a
            }
            (Reconnecting, DialFailed) => {
                self.attempt = self.attempt.saturating_add(1);
                vec![ScheduleBackoff(backoff_delay(
                    self.attempt,
                    self.base,
                    self.max,
                ))]
            }
            (Reconnecting, Disconnect) => {
                self.state = Disconnected;
                let mut a = Vec::new();
                if self.proxy_set {
                    self.proxy_set = false;
                    a.push(ClearProxy);
                }
                a.push(Emit(Disconnected));
                a
            }

            // --- everything else is a no-op ---
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Action::*;
    use super::*;

    fn machine(kill_switch: bool) -> Machine {
        Machine::new(
            kill_switch,
            Duration::from_millis(500),
            Duration::from_secs(30),
        )
    }

    #[test]
    fn backoff_grows_and_caps() {
        let base = Duration::from_millis(500);
        let max = Duration::from_secs(30);
        assert_eq!(backoff_delay(0, base, max), Duration::from_millis(500));
        assert_eq!(backoff_delay(1, base, max), Duration::from_secs(1));
        assert_eq!(backoff_delay(2, base, max), Duration::from_secs(2));
        assert_eq!(backoff_delay(10, base, max), max); // capped
        assert_eq!(backoff_delay(u32::MAX, base, max), max); // no overflow
    }

    #[test]
    fn connect_dials() {
        let mut m = machine(true);
        assert_eq!(
            m.handle(Input::Connect),
            vec![Emit(State::Connecting), Dial]
        );
        assert_eq!(m.state, State::Connecting);
    }

    #[test]
    fn connect_success_sets_proxy_and_serves() {
        let mut m = machine(true);
        m.handle(Input::Connect);
        let actions = m.handle(Input::DialSucceeded);
        assert_eq!(
            actions,
            vec![SetProxy, StartServing, Emit(State::Connected)]
        );
        assert_eq!(m.state, State::Connected);
    }

    #[test]
    fn initial_dial_failure_goes_to_error() {
        let mut m = machine(true);
        m.handle(Input::Connect);
        assert_eq!(m.handle(Input::DialFailed), vec![Emit(State::Error)]);
        assert_eq!(m.state, State::Error);
    }

    #[test]
    fn error_then_connect_redials() {
        let mut m = machine(true);
        m.handle(Input::Connect);
        m.handle(Input::DialFailed);
        assert_eq!(
            m.handle(Input::Connect),
            vec![Emit(State::Connecting), Dial]
        );
    }

    #[test]
    fn drop_with_killswitch_keeps_proxy() {
        let mut m = machine(true);
        m.handle(Input::Connect);
        m.handle(Input::DialSucceeded);
        let actions = m.handle(Input::TunnelDropped);
        // No ClearProxy: apps fail closed.
        assert!(!actions.contains(&ClearProxy));
        assert!(actions.contains(&StopServing));
        assert!(actions.contains(&Emit(State::Reconnecting)));
        assert_eq!(m.state, State::Reconnecting);
    }

    #[test]
    fn drop_without_killswitch_clears_proxy() {
        let mut m = machine(false);
        m.handle(Input::Connect);
        m.handle(Input::DialSucceeded);
        let actions = m.handle(Input::TunnelDropped);
        assert!(actions.contains(&ClearProxy));
        assert_eq!(m.state, State::Reconnecting);
    }

    #[test]
    fn reconnect_after_drop_does_not_reset_proxy_when_kept() {
        let mut m = machine(true); // kill switch keeps proxy set across the drop
        m.handle(Input::Connect);
        m.handle(Input::DialSucceeded);
        m.handle(Input::TunnelDropped);
        m.handle(Input::BackoffElapsed); // => Dial
        let actions = m.handle(Input::DialSucceeded);
        // Proxy was never cleared, so no second SetProxy.
        assert!(!actions.contains(&SetProxy));
        assert!(actions.contains(&StartServing));
        assert_eq!(m.state, State::Connected);
    }

    #[test]
    fn reconnecting_failure_increases_backoff() {
        let mut m = machine(true);
        m.handle(Input::Connect);
        m.handle(Input::DialSucceeded);
        m.handle(Input::TunnelDropped); // attempt=0 scheduled
        m.handle(Input::BackoffElapsed); // Dial
        let a1 = m.handle(Input::DialFailed); // attempt=1
        assert_eq!(a1, vec![ScheduleBackoff(Duration::from_secs(1))]);
        m.handle(Input::BackoffElapsed);
        let a2 = m.handle(Input::DialFailed); // attempt=2
        assert_eq!(a2, vec![ScheduleBackoff(Duration::from_secs(2))]);
    }

    #[test]
    fn user_disconnect_clears_proxy() {
        let mut m = machine(true);
        m.handle(Input::Connect);
        m.handle(Input::DialSucceeded);
        let actions = m.handle(Input::Disconnect);
        assert!(actions.contains(&ClearProxy));
        assert!(actions.contains(&StopServing));
        assert!(actions.contains(&Emit(State::Disconnected)));
        assert_eq!(m.state, State::Disconnected);
    }

    #[test]
    fn disconnect_while_reconnecting_stops_cleanly() {
        let mut m = machine(false); // proxy was cleared on the drop
        m.handle(Input::Connect);
        m.handle(Input::DialSucceeded);
        m.handle(Input::TunnelDropped); // clears proxy (no kill switch)
        let actions = m.handle(Input::Disconnect);
        // Proxy already cleared, so only the state emit.
        assert_eq!(actions, vec![Emit(State::Disconnected)]);
        assert_eq!(m.state, State::Disconnected);
    }
}
