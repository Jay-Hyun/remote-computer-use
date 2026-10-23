//! 속도 제한: 토큰당 분당 호출 수, 노드 전체 하루 호출 수(UTC 날짜 기준).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use time::Date;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Minute,
    Day,
}

#[derive(Default)]
struct State {
    windows: HashMap<String, (Instant, u32)>,
    day: Option<Date>,
    day_count: u32,
}

pub struct Limiter {
    per_minute: u32,
    per_day: u32,
    state: Mutex<State>,
}

impl Limiter {
    pub fn new(per_minute: u32, per_day: u32) -> Limiter {
        Limiter {
            per_minute,
            per_day,
            state: Mutex::new(State::default()),
        }
    }

    /// 호출 한 번을 센다. 한도를 넘으면 세지 않고 어느 한도인지 돌려준다.
    pub fn check(&self, token_id: &str, now: Instant, today: Date) -> Result<(), Limit> {
        let mut st = self.state.lock().unwrap();
        if st.day != Some(today) {
            st.day = Some(today);
            st.day_count = 0;
        }
        if st.day_count >= self.per_day {
            return Err(Limit::Day);
        }
        // 오래된 창은 버려 맵이 커지지 않게 한다.
        st.windows.retain(|_, (start, _)| {
            now.saturating_duration_since(*start) < Duration::from_secs(120)
        });
        let slot = st.windows.entry(token_id.to_string()).or_insert((now, 0));
        if now.saturating_duration_since(slot.0) >= Duration::from_secs(60) {
            *slot = (now, 0);
        }
        if slot.1 >= self.per_minute {
            return Err(Limit::Minute);
        }
        slot.1 += 1;
        st.day_count += 1;
        Ok(())
    }
}
