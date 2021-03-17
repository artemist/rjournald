use std::time::Duration;
use libc::{timespec,clock_gettime,CLOCK_MONOTONIC_RAW};

pub fn monotonic_time_now() -> anyhow::Result<Duration> {
    let mut t = timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { clock_gettime(CLOCK_MONOTONIC_RAW, &mut t) };
    if ret == -1 {
        Err(anyhow::anyhow!("Failed to get CLOCK_MONOTONIC_RAW"))
    } else {
        // CLOCK_MONOTONIC_RAW is guaranteed to be positive and it won't overflow until after Earth
        // is destroyed so this conversion should be safe.
        Ok(Duration::new(t.tv_sec as u64, t.tv_nsec as u32))
    }
}
