//! Concurrency, rate, origin admission, and circuit controls.

use super::{
    cache::ResourceKey,
    fetch::{FetchError, FetchErrorKind},
};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use moka::future::Cache;
use std::{
    collections::HashMap,
    net::IpAddr,
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};

pub(super) const MIN_FAILURE_BACKOFF: Duration = Duration::from_secs(5);
pub(super) const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(5 * 60);
pub(super) const COALESCED_FAILURE_TTL: Duration = Duration::from_millis(50);
pub(super) const RESOLUTION_DEADLINE: Duration = Duration::from_millis(1_800);

/// Bounds work triggered by one resolver request.
#[derive(Clone, Debug)]
pub struct Limits {
    pub inbound_body_bytes: usize,
    pub active_handlers: usize,
    pub outbound_fetches: usize,
    pub global_fetch_rate: u32,
    pub global_fetch_burst: u32,
    pub origin_fetch_rate: u32,
    pub origin_fetch_burst: u32,
    pub ip_fetch_rate: u32,
    pub ip_fetch_burst: u32,
    pub new_origins_per_minute: usize,
    pub state_entries: u64,
    pub max_keys: usize,
    pub resolution_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            inbound_body_bytes: 8 * 1024,
            active_handlers: 64,
            outbound_fetches: 32,
            global_fetch_rate: 16,
            global_fetch_burst: 32,
            origin_fetch_rate: 2,
            origin_fetch_burst: 4,
            ip_fetch_rate: 8,
            ip_fetch_burst: 16,
            new_origins_per_minute: 256,
            state_entries: 1_024,
            max_keys: 32,
            resolution_timeout: RESOLUTION_DEADLINE,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), &'static str> {
        const MAX_BODY: usize = 65_536;
        const MAX_HANDLERS: usize = 4_096;
        const MAX_FETCHES: usize = 1_024;
        const MAX_RATE: u32 = 1_000_000;
        const MAX_ORIGINS: usize = 100_000;
        const MAX_STATE: u64 = 100_000;
        const MAX_KEYS: usize = 1_024;
        const MAX_TIMEOUT: Duration = RESOLUTION_DEADLINE;
        if !(1..=MAX_BODY).contains(&self.inbound_body_bytes) {
            return Err("inbound_body_bytes must be between 1 and 65536");
        }
        if !(1..=MAX_HANDLERS).contains(&self.active_handlers) {
            return Err("active_handlers must be between 1 and 4096");
        }
        if !(1..=MAX_FETCHES).contains(&self.outbound_fetches) {
            return Err("outbound_fetches must be between 1 and 1024");
        }
        for (name, rate, burst) in [
            (
                "global_fetch",
                self.global_fetch_rate,
                self.global_fetch_burst,
            ),
            (
                "origin_fetch",
                self.origin_fetch_rate,
                self.origin_fetch_burst,
            ),
            ("ip_fetch", self.ip_fetch_rate, self.ip_fetch_burst),
        ] {
            if !(1..=MAX_RATE).contains(&rate) || !(1..=MAX_RATE).contains(&burst) || burst < rate {
                return Err(match name {
                    "global_fetch" => {
                        "global fetch rate and burst must be between 1 and 1000000, with burst at least rate"
                    }
                    "origin_fetch" => {
                        "origin fetch rate and burst must be between 1 and 1000000, with burst at least rate"
                    }
                    _ => {
                        "ip fetch rate and burst must be between 1 and 1000000, with burst at least rate"
                    }
                });
            }
        }
        if !(1..=MAX_ORIGINS).contains(&self.new_origins_per_minute) {
            return Err("new_origins_per_minute must be between 1 and 100000");
        }
        if !(1..=MAX_STATE).contains(&self.state_entries) {
            return Err("state_entries must be between 1 and 100000");
        }
        if self.new_origins_per_minute as u64 > self.state_entries {
            return Err("new_origins_per_minute must not exceed state_entries");
        }
        if !(1..=MAX_KEYS).contains(&self.max_keys) {
            return Err("max_keys must be between 1 and 1024");
        }
        if self.resolution_timeout.is_zero() || self.resolution_timeout > MAX_TIMEOUT {
            return Err("resolution_timeout must be between 1 and 1800 milliseconds");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct CircuitState {
    consecutive_failures: u32,
    open_count: u32,
    open_until: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CircuitTransition {
    Opened,
    Closed,
}

impl CircuitTransition {
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Closed => "closed",
        }
    }
}

pub(super) struct WorkControls {
    outbound: Arc<Semaphore>,
    global: Arc<DefaultDirectRateLimiter>,
    origins: Cache<String, Arc<DefaultDirectRateLimiter>>,
    ips: Cache<IpAddr, Arc<DefaultDirectRateLimiter>>,
    new_origins: Mutex<HashMap<String, Instant>>,
    circuits: Cache<ResourceKey, Arc<Mutex<CircuitState>>>,
    limits: Limits,
}

impl WorkControls {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            outbound: Arc::new(Semaphore::new(limits.outbound_fetches)),
            global: Arc::new(limiter(limits.global_fetch_rate, limits.global_fetch_burst)),
            origins: Cache::builder()
                .max_capacity(limits.state_entries)
                .time_to_idle(Duration::from_secs(5 * 60))
                .build(),
            ips: Cache::builder()
                .max_capacity(limits.state_entries)
                .time_to_idle(Duration::from_secs(5 * 60))
                .build(),
            new_origins: Mutex::new(HashMap::new()),
            circuits: Cache::builder()
                .max_capacity(limits.state_entries)
                .time_to_idle(Duration::from_secs(10 * 60))
                .build(),
            limits,
        }
    }

    async fn circuit(&self, key: &ResourceKey) -> Arc<Mutex<CircuitState>> {
        self.circuits
            .get_with(key.clone(), async {
                Arc::new(Mutex::new(CircuitState::default()))
            })
            .await
    }

    pub(super) async fn check_circuit(&self, key: &ResourceKey) -> Result<(), FetchError> {
        let circuit = self.circuit(key).await;
        let state = circuit.lock().await;
        if state.open_until.is_some_and(|until| until > Instant::now()) {
            return Err(FetchError::new(FetchErrorKind::CircuitOpen));
        }
        Ok(())
    }

    pub(super) async fn success(&self, key: &ResourceKey) -> Option<CircuitTransition> {
        let circuit = self.circuit(key).await;
        let mut state = circuit.lock().await;
        let transition = (state.consecutive_failures > 0 || state.open_until.is_some())
            .then_some(CircuitTransition::Closed);
        *state = CircuitState::default();
        transition
    }

    pub(super) async fn failure_backoff(
        &self,
        key: &ResourceKey,
        retry_after: Option<Duration>,
    ) -> (Duration, Option<CircuitTransition>) {
        let circuit = self.circuit(key).await;
        let mut state = circuit.lock().await;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let exponent = state.consecutive_failures.saturating_sub(1).min(6);
        let backoff = MIN_FAILURE_BACKOFF
            .saturating_mul(1u32 << exponent)
            .min(MAX_FAILURE_BACKOFF)
            .max(
                retry_after
                    .unwrap_or(Duration::ZERO)
                    .min(MAX_FAILURE_BACKOFF),
            );
        let transition = if state.consecutive_failures >= 3 {
            let open_exponent = state.open_count.min(4);
            let open_for = Duration::from_secs(30)
                .saturating_mul(1u32 << open_exponent)
                .min(MAX_FAILURE_BACKOFF);
            state.open_count = state.open_count.saturating_add(1);
            state.open_until = Some(Instant::now() + open_for);
            Some(CircuitTransition::Opened)
        } else {
            None
        };
        (backoff, transition)
    }

    pub(super) async fn circuit_remaining(&self, key: &ResourceKey) -> Duration {
        let circuit = self.circuit(key).await;
        let state = circuit.lock().await;
        state
            .open_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
            .unwrap_or(COALESCED_FAILURE_TTL)
    }

    pub(super) async fn begin_fetch(
        &self,
        origin: String,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, FetchError> {
        let permit = Arc::clone(&self.outbound)
            .try_acquire_owned()
            .map_err(|_| FetchError::new(FetchErrorKind::Overloaded))?;
        if self.global.check().is_err() {
            return Err(FetchError::new(FetchErrorKind::RateLimited));
        }
        let origin_is_new = self.origins.get(&origin).await.is_none();
        if origin_is_new {
            let now = Instant::now();
            let mut origins = self.new_origins.lock().await;
            origins.retain(|_, seen| now.duration_since(*seen) < Duration::from_secs(60));
            let state_limit = usize::try_from(self.limits.state_entries).unwrap_or(usize::MAX);
            if !origins.contains_key(&origin)
                && (origins.len() >= self.limits.new_origins_per_minute
                    || origins.len() >= state_limit)
            {
                return Err(FetchError::new(FetchErrorKind::RateLimited));
            }
            origins.insert(origin.clone(), now);
        }
        let origin_limiter = self
            .origins
            .get_with(origin, async {
                Arc::new(limiter(
                    self.limits.origin_fetch_rate,
                    self.limits.origin_fetch_burst,
                ))
            })
            .await;
        if origin_limiter.check().is_err() {
            return Err(FetchError::new(FetchErrorKind::RateLimited));
        }
        Ok(permit)
    }

    pub(super) async fn check_ip(&self, ip: IpAddr) -> Result<(), FetchError> {
        let ip_limiter = self
            .ips
            .get_with(ip, async {
                Arc::new(limiter(
                    self.limits.ip_fetch_rate,
                    self.limits.ip_fetch_burst,
                ))
            })
            .await;
        if ip_limiter.check().is_err() {
            return Err(FetchError::new(FetchErrorKind::RateLimited));
        }
        Ok(())
    }
}

fn limiter(rate: u32, burst: u32) -> DefaultDirectRateLimiter {
    let quota = Quota::per_second(NonZeroU32::new(rate).expect("validated non-zero rate"))
        .allow_burst(NonZeroU32::new(burst).expect("validated non-zero burst"));
    RateLimiter::direct(quota)
}

#[cfg(test)]
mod tests {
    use super::{Limits, RESOLUTION_DEADLINE};

    #[test]
    fn validation_rejects_a_burst_below_the_refill_rate() {
        let limits = Limits {
            global_fetch_rate: 100,
            global_fetch_burst: 1,
            ..Limits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(
                "global fetch rate and burst must be between 1 and 1000000, with burst at least rate"
            )
        );
    }

    #[test]
    fn validation_rejects_a_resolution_timeout_above_the_end_to_end_budget() {
        let limits = Limits {
            resolution_timeout: RESOLUTION_DEADLINE + std::time::Duration::from_millis(1),
            ..Limits::default()
        };
        assert_eq!(
            limits.validate(),
            Err("resolution_timeout must be between 1 and 1800 milliseconds")
        );
    }
}
