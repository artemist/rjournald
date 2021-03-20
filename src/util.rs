use nix::time::{clock_gettime, ClockId};
use std::time::Duration;

pub fn monotonic_time_now() -> anyhow::Result<Duration> {
    Ok(clock_gettime(ClockId::CLOCK_MONOTONIC_RAW)?.into())
}
