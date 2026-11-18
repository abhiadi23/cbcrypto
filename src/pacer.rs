use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};


/// Port of the Python `AdaptiveBucket` (token bucket + slow start + additive increase,
/// multiplicative decrease), shared by all connections of one transfer.
pub struct Pacer {
    st: Mutex<PacerSt>,
}

struct PacerSt {
    rate: f64,
    burst: f64,
    tokens: f64,
    last_refill: Instant,
    ceiling: f64,
    floor: f64,
    step: f64,
    growth: f64,
    ss_cap: f64,
    slow_start: bool,
    last_up: Instant,
    last_down: Option<Instant>,
    /// never cut below this (unless floods keep coming back-to-back)
    soft_floor: f64,
    /// after a flood, climb back quickly to here (a little under where it happened)
    target: f64,
    /// floods that arrived within a few seconds of each other
    storm: u32,
    /// after a flood, do not probe above this (just under where it happened) for a while
    hold_level: f64,
    hold_until: Option<Instant>,
}

pub struct PacerCfg {
    pub rate: f64,
    pub burst: f64,
    pub ceiling: f64,
    pub step: f64,
    pub growth: f64,
    pub slow_start_cap: f64,
}

impl Pacer {
    pub fn new(c: &PacerCfg) -> Self {
        Self::new_at(c, Instant::now())
    }

    pub fn new_at(c: &PacerCfg, now: Instant) -> Self {
        let ss_cap = c.slow_start_cap.min(c.ceiling);
        Pacer {
            st: Mutex::new(PacerSt {
                rate: c.rate,
                burst: c.burst,
                tokens: c.burst,
                last_refill: now,
                ceiling: c.ceiling,
                floor: 1.0,
                step: c.step,
                growth: c.growth,
                ss_cap,
                slow_start: c.growth > 1.0 && c.rate < ss_cap,
                last_up: now,
                last_down: None,
                soft_floor: (ss_cap * 0.5).min(c.rate * 0.75).max(1.0),
                target: 0.0,
                storm: 0,
                hold_level: f64::INFINITY,
                hold_until: None,
            }),
        }
    }

    fn refill(s: &mut PacerSt, now: Instant) {
        let el = now.duration_since(s.last_refill).as_secs_f64();
        s.tokens = s.burst.min(s.tokens + el * s.rate);
        s.last_refill = now;
    }

    /// Block until one request may be sent. False if the transfer was cancelled meanwhile.
    pub fn acquire(&self, cancel: &AtomicBool) -> bool {
        loop {
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
            let wait = {
                let mut s = self.st.lock().unwrap();
                Self::refill(&mut s, Instant::now());
                if s.tokens >= 1.0 {
                    s.tokens -= 1.0;
                    return true;
                }
                (1.0 - s.tokens) / s.rate.max(0.001)
            };
            std::thread::sleep(Duration::from_secs_f64(wait.min(0.05)));
        }
    }

    pub fn on_success(&self) {
        self.on_success_at(Instant::now());
    }

    pub fn on_success_at(&self, now: Instant) {
        let mut s = self.st.lock().unwrap();
        if s.slow_start {
            if now.duration_since(s.last_up).as_secs_f64() >= 0.25 {
                s.last_up = now;
                Self::refill(&mut s, now);
                let nr = (s.rate * s.growth).min(s.ss_cap);
                if nr >= s.ss_cap {
                    s.slow_start = false;
                }
                s.rate = nr;
            }
            return;
        }
        let since_down = s.last_down.map_or(f64::INFINITY, |d| now.duration_since(d).as_secs_f64());

        let cap = match s.hold_until {
            Some(t) if now < t => s.hold_level.min(s.ceiling),
            _ => s.ceiling,
        };

        // fast recovery after a flood: close most of the gap to the rate we were
        // at, instead of crawling back at +step per second
        if s.rate < s.target {
            if since_down >= 1.0 && now.duration_since(s.last_up).as_secs_f64() >= 0.5 {
                s.last_up = now;
                Self::refill(&mut s, now);
                let gap = s.target - s.rate;
                s.rate = (s.rate + (gap * 0.3).max(s.step)).min(s.target).min(cap);
            }
            return;
        }

        // at or above the old level: probe upwards slowly, as before
        if now.duration_since(s.last_up).as_secs_f64() >= 1.0 && since_down >= 2.0 {
            s.last_up = now;
            Self::refill(&mut s, now);
            s.rate = (s.rate + s.step).min(cap).max(s.rate.min(cap));
        }
    }

    pub fn on_flood(&self) {
        self.on_flood_at(Instant::now());
    }

    /// current request rate (requests/s)
    #[allow(dead_code)]
    pub fn rate(&self) -> f64 {
        self.st.lock().unwrap().rate
    }

    pub fn on_flood_at(&self, now: Instant) {
        let mut s = self.st.lock().unwrap();
        if s.last_down.map_or(false, |d| now.duration_since(d).as_secs_f64() < 1.0) {
            return;
        }
        // back-to-back floods mean the server really is at its limit: back off hard.
        // A flood after a calm spell was probably a blip: cut gently and climb back.
        let stormy = s.last_down.map_or(false, |d| now.duration_since(d).as_secs_f64() < 4.0);
        s.storm = if stormy { s.storm + 1 } else { 1 };

        let before = s.rate;
        let mult = if s.storm >= 3 {
            0.7
        } else if s.slow_start {
            0.8
        } else {
            0.92
        };
        let floor = if s.storm >= 3 { s.floor } else { s.soft_floor.min(before).max(s.floor) };

        s.slow_start = false;
        s.rate = (before * mult).max(floor);
        s.target = if s.storm >= 2 { s.rate } else { (before * 0.92).max(s.rate) };
        // a lone flood is a blip: climb straight back. Floods that keep returning mean
        // there is a real limit near here, so stay just under it for a while.
        let repeat = s.last_down.map_or(false, |d| now.duration_since(d).as_secs_f64() < 30.0);
        if repeat {
            s.hold_level = (before * 0.97).max(s.rate);
            s.hold_until = Some(now + Duration::from_secs(20));
        } else {
            s.hold_until = None;
        }
        s.last_down = Some(now);
        s.last_up = now;
        Self::refill(&mut s, now);
    }

}


#[cfg(test)]
mod sim {
    use super::*;

    fn cfg() -> PacerCfg {
        // a normal (non-premium) account: what core_transfer passes for downloads
        PacerCfg { rate: 8.0, burst: 8.0, ceiling: 150.0, step: 0.5, growth: 1.5, slow_start_cap: 40.0 }
    }

    /// Drive the pacer for `secs` seconds in 50 ms ticks. `flood_at(t, rate)` says whether
    /// the server refuses a request at that moment. Returns (rate trace per second, floods).
    fn run(secs: usize, mut flood_at: impl FnMut(f64, f64) -> bool) -> (Vec<f64>, usize) {
        let t0 = Instant::now();
        let p = Pacer::new_at(&cfg(), t0);
        let (mut trace, mut floods, mut last_flood) = (Vec::new(), 0, -10.0f64);
        for tick in 0..secs * 20 {
            let t = tick as f64 * 0.05;
            let now = t0 + Duration::from_secs_f64(t);
            let rate = p.rate();
            if flood_at(t, rate) && t - last_flood >= 1.0 {
                p.on_flood_at(now);
                floods += 1;
                last_flood = t;
            } else {
                p.on_success_at(now);
            }
            if tick % 20 == 0 {
                trace.push(p.rate());
            }
        }
        (trace, floods)
    }

    fn avg(v: &[f64]) -> f64 { v.iter().sum::<f64>() / v.len() as f64 }

    fn secs_to_reach(trace: &[f64], from: usize, level: f64) -> Option<usize> {
        trace[from..].iter().position(|r| *r >= level)
    }

    /// B: Telegram refuses once during the ramp-up (t≈1 s, rate then ~27-40), later once more.
    #[test]
    fn isolated_floods() {
        let mut fired = [false; 3];
        let (tr, floods) = run(120, |t, _| {
            for (i, at) in [0.9f64, 40.0, 80.0].iter().enumerate() {
                if !fired[i] && t >= *at {
                    fired[i] = true;
                    return true;
                }
            }
            false
        });
        println!("\n[B] isolated floods at 0.9 s, 40 s, 80 s (server could do >40/s)");
        println!("    rate each 10 s: {:?}", tr.iter().step_by(10).map(|r| r.round() as i64).collect::<Vec<_>>());
        println!("    avg {:.1}/s   min after ramp {:.1}/s   floods {}", avg(&tr[3..]), tr[3..].iter().cloned().fold(1e9, f64::min), floods);
        println!("    seconds to get back to 36/s after the flood at 40 s: {:?}", secs_to_reach(&tr, 41, 36.0));
        // a one-off FloodWait must not leave a transfer crawling at ~half speed for half a minute
        assert!(tr[10] >= 25.0, "rate 10 s after a ramp-up flood: {}", tr[10]);
        assert!(tr[3..].iter().cloned().fold(1e9, f64::min) >= 20.0);
        assert!(secs_to_reach(&tr, 41, 36.0).unwrap() <= 5);
        assert!(avg(&tr[3..]) >= 40.0);
    }

    /// C: server really only sustains 28 req/s; floods whenever we exceed it.
    #[test]
    fn hard_limit_28() {
        let (tr, floods) = run(120, |_, rate| rate > 28.0);
        println!("\n[C] server sustains only 28/s");
        println!("    rate each 10 s: {:?}", tr.iter().step_by(10).map(|r| r.round() as i64).collect::<Vec<_>>());
        println!("    avg {:.1}/s   floods {}", avg(&tr[5..]), floods);
        // against a real limit it must settle just under it without a flood storm
        assert!(floods <= 12, "{floods} floods");
        assert!(avg(&tr[5..]) >= 26.0 && avg(&tr[5..]) <= 28.5);
    }

    /// D: no flood at all.
    #[test]
    fn no_floods() {
        let (tr, floods) = run(60, |_, _| false);
        println!("\n[D] no floods: avg {:.1}/s, floods {}", avg(&tr[3..]), floods);
        assert!(floods == 0 && avg(&tr[3..]) >= 40.0);
    }

    /// E: floods one after another (server clearly saturated) must back off hard, not drift.
    #[test]
    fn storm_backs_off_hard() {
        let (tr, floods) = run(30, |t, _| t >= 5.0 && t < 12.0);
        println!("\n[E] flood storm 5-12 s: rate each second {:?}", tr.iter().map(|r| r.round() as i64).collect::<Vec<_>>());
        assert!(floods >= 3);
        assert!(tr[13..].iter().cloned().fold(1e9, f64::min) < 25.0 || tr[12] < 25.0, "no deeper back-off in a storm");
    }
            }
