pub struct LocalDateTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: i32,
}

#[cfg(windows)]
#[repr(C)]
struct SystemTime {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

#[cfg(windows)]
#[allow(non_snake_case)]
extern "system" {
    fn GetLocalTime(lpSystemTime: *mut SystemTime);
}

#[cfg(windows)]
pub fn current_local_datetime() -> LocalDateTime {
    unsafe {
        let mut t: SystemTime = std::mem::zeroed();
        GetLocalTime(&mut t);
        LocalDateTime {
            year: t.w_year as i32,
            month: t.w_month as i32,
            day: t.w_day as i32,
            hour: t.w_hour as i32,
            minute: t.w_minute as i32,
            second: t.w_second as i32,
        }
    }
}

#[cfg(not(windows))]
pub fn current_local_datetime() -> LocalDateTime {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = kg_shared::license::unix_seconds_to_local_date(secs);
    let day_secs = (secs.rem_euclid(86400)) as i32;
    LocalDateTime {
        year: y,
        month: m,
        day: d,
        hour: day_secs / 3600,
        minute: (day_secs / 60) % 60,
        second: day_secs % 60,
    }
}
