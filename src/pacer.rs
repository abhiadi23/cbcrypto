use std::collections::VecDeque;
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
    /// when requests were actually let through (last ~2 s): the rate we really sent at, which
    /// is what the server judged, not the configured one
    grants: VecDeque<Instant>,
    born: Instant,
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
                grants: VecDeque::new(),
                born: now,
            }),
        }
    }

    fn refill(s: &mut PacerSt, now: Instant) {
        let el = now.duration_since(s.last_refill).as_secs_f64();
        s.tokens = s.burst.min(s.tokens + el * s.rate);
        s.last_refill = now;
    }

    fn note_grant(s: &mut PacerSt, now: Instant, n: usize) {
        for _ in 0..n {
            s.grants.push_back(now);
        }
        while s.grants.front().map_or(false, |t| now.duration_since(*t).as_secs_f64() > 2.0) {
            s.grants.pop_front();
        }
    }

    /// Requests per second actually let through over the last second (or over however much of it has
    /// elapsed, right after the start, so a flood in the first moments is not read as a slow sender).
    fn sent_rate(s: &PacerSt, now: Instant) -> Option<f64> {
        let window = now.duration_since(s.born).as_secs_f64().min(1.0).max(0.25);
        let n = s.grants.iter().filter(|t| now.duration_since(**t).as_secs_f64() <= window).count();
        // too few samples to say anything about the rate we were sending at
        (n >= 8).then(|| n as f64 / window)
    }

    /// Test hook: pretend `n` requests were let through at `now`.
    #[cfg(test)]
    pub fn record_grants_at(&self, now: Instant, n: usize) {
        Self::note_grant(&mut self.st.lock().unwrap(), now, n);
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
                    Self::note_grant(&mut s, Instant::now(), 1);
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

        // What the server judged is what we really sent, which can be below the configured rate
        // (few connections, slow link) or a little above it (bursts).
        // The server complained while we were sending at least the configured rate, so cut from that
        // (or from more, if bursts pushed us above it). A measured rate below the configured one is not
        // trusted: it is usually a window spent stalled by the previous flood, and cutting from it
        // would compound the cut.
        let level = match Self::sent_rate(&s, now) {
            Some(sent) => sent.min(s.rate * 1.25).max(s.rate),
            None => s.rate,
        };

        let mult = if s.storm >= 3 { 0.7 } else { 0.8 };
        let floor = if s.storm >= 3 { s.floor } else { s.soft_floor.min(level).max(s.floor) };

        s.slow_start = false;
        s.rate = (level.min(s.rate.max(level)) * mult).max(floor).min(s.rate.max(floor));
        // The limit is somewhere just below `level`: climb straight back to just under it, then stay
        // there for a while instead of probing over the edge again and again.
        let hold = (level * 0.93).max(s.rate);
        s.target = if s.storm >= 2 { s.rate } else { hold };
        s.hold_level = hold;
        s.hold_until = Some(now + Duration::from_secs(45));
        if std::env::var_os("CBCRYPTO_DEBUG_PACER").is_some() {
            eprintln!("[pacer] flood: level {:.1} rate {:.1} -> hold {:.1} storm {} floor {:.1}", level, s.rate, hold, s.storm, s.soft_floor);
        }
        s.last_down = Some(now);
        s.last_up = now;
        Self::refill(&mut s, now);
    }
}


#[cfg(test)]
mod sim {
    use super::*;

    /// The stable band used for bots and normal accounts: start 32/s, never above 50/s (1 MiB chunks).
    fn band() -> PacerCfg {
        PacerCfg { rate: 32.0, burst: 8.0, ceiling: 50.0, step: 0.5, growth: 1.1, slow_start_cap: 50.0 }
    }

    /// What the engine used before: start at 8/s, slow start to 40/s, then probe slowly up to 150/s.
    fn legacy_cfg() -> PacerCfg {
        PacerCfg { rate: 8.0, burst: 8.0, ceiling: 150.0, step: 0.5, growth: 1.5, slow_start_cap: 40.0 }
    }

    /// Drive the pacer for `secs` seconds in 50 ms ticks, sending at the pacer's current rate.
    /// `flood_at(t, sending_rate)` says whether the server refuses at that moment.
    /// Returns (configured rate per second, floods).
    fn run_cfg(cfg: PacerCfg, secs: usize, mut flood_at: impl FnMut(f64, f64) -> bool) -> (Vec<f64>, usize) {
        let t0 = Instant::now();
        let p = Pacer::new_at(&cfg, t0);
        let (mut trace, mut floods, mut last_flood, mut carry) = (Vec::new(), 0, -10.0f64, 0.0f64);
        for tick in 0..secs * 20 {
            let t = tick as f64 * 0.05;
            let now = t0 + Duration::from_secs_f64(t);
            let rate = p.rate();
            carry += rate * 0.05;
            let n = carry.floor();
            carry -= n;
            p.record_grants_at(now, n as usize);
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

    fn run(secs: usize, flood_at: impl FnMut(f64, f64) -> bool) -> (Vec<f64>, usize) {
        run_cfg(band(), secs, flood_at)
    }

    fn avg(v: &[f64]) -> f64 { v.iter().sum::<f64>() / v.len() as f64 }
    fn min(v: &[f64]) -> f64 { v.iter().cloned().fold(1e9, f64::min) }
    fn max(v: &[f64]) -> f64 { v.iter().cloned().fold(0.0, f64::max) }
    fn trace10(tr: &[f64]) -> Vec<i64> { tr.iter().step_by(10).map(|r| r.round() as i64).collect() }

    /// No floods: straight to the top of the band and stay there.
    #[test]
    fn no_floods_touches_the_cap() {
        let (tr, floods) = run(60, |_, _| false);
        println!("\n[A] no floods: rate each 10 s {:?}  max {:.0}", trace10(&tr), max(&tr));
        assert_eq!(floods, 0);
        assert!(tr[1] >= 45.0, "must be at speed within a second, small files cannot wait: {}", tr[1]);
        assert!(max(&tr) <= 50.0 + 1e-9, "never above the cap");
        assert!(avg(&tr[1..]) >= 48.0);
    }

    /// Isolated floods (blips) during and after the ramp must not leave the transfer crawling.
    #[test]
    fn isolated_floods_stay_in_the_band() {
        let mut fired = [false; 3];
        let (tr, floods) = run(120, |t, _| {
            for (i, at) in [0.4f64, 40.0, 80.0].iter().enumerate() {
                if !fired[i] && t >= *at {
                    fired[i] = true;
                    return true;
                }
            }
            false
        });
        println!("\n[B] isolated floods at 0.4 s, 40 s, 80 s: rate each 10 s {:?}", trace10(&tr));
        println!("    avg {:.1}/s  min {:.1}/s  floods {}", avg(&tr[1..]), min(&tr[1..]), floods);
        assert!(min(&tr[1..]) >= 20.0, "never below 20/s on a blip: {}", min(&tr[1..]));
        assert!(avg(&tr[1..]) >= 30.0 && avg(&tr[1..]) <= 50.0);
        assert!(tr[10] >= 30.0, "rate 10 s after a flood during the ramp: {}", tr[10]);
    }

    /// The server only tolerates 36/s (well inside the band): settle just under it, with few floods.
    #[test]
    fn learns_a_real_limit_without_a_flood_storm() {
        let (tr, floods) = run(180, |_, rate| rate > 36.0);
        println!("\n[C] server limit 36/s: rate each 10 s {:?}", trace10(&tr));
        println!("    avg {:.1}/s  min {:.1}/s  floods {} in 180 s", avg(&tr[10..]), min(&tr[10..]), floods);
        assert!(floods <= 10, "{floods} floods");
        assert!(avg(&tr[10..]) >= 32.0 && avg(&tr[10..]) <= 37.0, "settles just under the limit");
        assert!(min(&tr[10..]) >= 28.0, "and does not oscillate deeply");
    }

    /// The server only tolerates 28/s: found within a few floods, then sat right at it.
    #[test]
    fn hard_limit_28() {
        let (tr, floods) = run(120, |_, r| r > 28.0);
        println!("\n[D] server limit 28/s: avg {:.1}/s min {:.1}/s floods {}", avg(&tr[10..]), min(&tr[10..]), floods);
        assert!(floods <= 8, "{floods} floods");
        assert!(avg(&tr[10..]) >= 25.0 && avg(&tr[10..]) <= 28.5);
    }

    /// Floods one after another (server clearly saturated) must back off hard, not drift.
    #[test]
    fn storm_backs_off_hard() {
        let (tr, floods) = run(40, |t, _| t >= 5.0 && t < 12.0);
        println!("\n[E] flood storm 5-12 s: rate each second {:?}", tr.iter().map(|r| r.round() as i64).collect::<Vec<_>>());
        assert!(floods >= 3);
        assert!(min(&tr[8..16]) < 24.0, "a real storm must be allowed below the soft floor");
    }

    /// A slower server limit than the floor (15/s): must still be respected eventually.
    #[test]
    fn a_very_low_limit_is_still_respected() {
        let (tr, floods) = run(120, |_, r| r > 15.0);
        println!("\n[F] server limit 15/s: rate each 10 s {:?} floods {}", trace10(&tr), floods);
        assert!(avg(&tr[60..]) <= 16.5 && avg(&tr[60..]) >= 12.0);
        assert!(floods <= 35);
    }
        }
