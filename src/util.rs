use nix::time::{clock_gettime, ClockId};
use std::convert::TryInto;
use std::time::Duration;

pub fn monotonic_time_now() -> anyhow::Result<Duration> {
    Ok(clock_gettime(ClockId::CLOCK_MONOTONIC_RAW)?.into())
}

pub trait ConstSliceExt<T> {
    fn const_slice<const LEN: usize>(&self, offset: usize) -> &[T; LEN];
}

impl<T> ConstSliceExt<T> for [T] {
    fn const_slice<const LEN: usize>(&self, offset: usize) -> &[T; LEN] {
        (self[offset..(offset + LEN)]).try_into().unwrap()
    }
}
