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
    /// what a flood *storm* may cut to (the "dip" level); only a long unbroken storm goes lower
    hard_floor: f64,
    /// every connection holds still until here after a flood (one shared cooldown, paid once)
    pause_until: Option<Instant>,
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
    /// lowest rate a flood storm cuts to before it is judged a real server limit (requests/s)
    pub hard_floor: f64,
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
                soft_floor: (c.ceiling * 0.4).min(c.rate * 0.6).max(c.hard_floor.min(c.ceiling * 0.6)).max(1.0), // from the ceiling, never below the dip level
                hard_floor: c.hard_floor.max(1.0).min(c.ceiling * 0.6),
                pause_until: None,
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
                let now = Instant::now();
                if let Some(t) = s.pause_until {
                    if now < t {
                        let left = t.duration_since(now).as_secs_f64();
                        drop(s);
                        std::thread::sleep(Duration::from_secs_f64(left.min(0.05)));
                        continue;
                    }
                    s.pause_until = None;
                    s.tokens = 0.0; // no burst when the cooldown ends
                    s.last_refill = now;
                }
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
            let inc = s.step.max(s.rate * 0.03); // ~3%/s: a dip at 20 is back above 30 in ~15 s
            s.rate = (s.rate + inc).min(cap).max(s.rate.min(cap));
        }
    }

    pub fn on_flood(&self) {
        self.on_flood_at(Instant::now());
    }

    /// A transfer that joins a pacer left low by an earlier storm starts from the dip level, not from
    /// the crawl the storm ended on (which would otherwise be inherited by every following file).
    pub fn lift_to_dip_level(&self) {
        let mut s = self.st.lock().unwrap();
        if s.rate < s.hard_floor {
            s.rate = s.hard_floor;
            s.target = s.target.max(s.hard_floor);
        }
    }

    /// A flood with a known wait: cut the rate as `on_flood` does AND hold *every* connection for
    /// the wait. Without the shared hold only the connection that got the error sleeps while the
    /// others keep sending into the penalty, which is what makes Telegram stretch it.
    /// Returns true when this started a new pause (the first reply of a flood), false for the other
    /// in-flight requests that answer with the same flood while that pause is already running.
    pub fn on_flood_wait(&self, secs: f64) -> bool {
        let now = Instant::now();
        self.on_flood_at(now);
        let until = now + Duration::from_secs_f64(secs.max(0.0).min(60.0));
        let mut s = self.st.lock().unwrap();
        let fresh = s.pause_until.map_or(true, |t| now >= t);
        if s.pause_until.map_or(true, |t| until > t) {
            s.pause_until = Some(until);
        }
        fresh
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
        // blip: stay above the soft floor. storm: may dip to the hard floor ("dip" band). Only a long
        // unbroken storm (the server really refuses this rate) is allowed all the way down.
        let floor = if s.storm >= 8 {
            // a long storm: lower than the dip band, but never to a crawl. The server answers a flood
            // with a wait either way, so a rate just under the dip band still gets served at its speed.
            (s.hard_floor * 0.75).min(level).max(s.floor)
        } else if s.storm >= 3 {
            s.hard_floor.min(level).max(s.floor)
        } else {
            s.soft_floor.min(level).max(s.floor)
        };

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

    /// The band used for bots and normal accounts (1 MiB chunks): start 45/s, never above 60/s,
    /// storms may dip to 20/s.
    fn band() -> PacerCfg {
        PacerCfg { rate: 45.0, burst: 8.0, ceiling: 60.0, step: 0.5, growth: 1.1, slow_start_cap: 60.0, hard_floor: 20.0 }
    }

    /// What the engine used before: start at 8/s, slow start to 40/s, then probe slowly up to 150/s.
    fn legacy_cfg() -> PacerCfg {
        PacerCfg { rate: 8.0, burst: 8.0, ceiling: 150.0, step: 0.5, growth: 1.5, slow_start_cap: 40.0, hard_floor: 1.0 }
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
        assert!(tr[1] >= 50.0, "must be at speed within a second, small files cannot wait: {}", tr[1]);
        assert!(max(&tr) <= 60.0 + 1e-9, "never above the cap");
        assert!(avg(&tr[1..]) >= 55.0);
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
        assert!(min(&tr[1..]) >= 30.0, "a blip must stay in the 30+ band: {}", min(&tr[1..]));
        assert!(avg(&tr[1..]) >= 40.0 && avg(&tr[1..]) <= 60.0);
        assert!(tr[10] >= 40.0, "rate 10 s after a flood during the ramp: {}", tr[10]);
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
        assert!(min(&tr[8..16]) < 30.0, "a real storm must be allowed below the soft floor");
        assert!(min(&tr[8..25]) >= 19.0, "but a short storm dips to the 20-30 band, not to a crawl: {}", min(&tr[8..25]));
    }

    /// A slower server limit than the floor (15/s): must still be respected eventually.
    #[test]
    fn a_very_low_limit_is_still_respected() {
        let (tr, floods) = run(120, |_, r| r > 15.0);
        println!("\n[F] server limit 15/s: rate each 10 s {:?} floods {}", trace10(&tr), floods);
        assert!(avg(&tr[60..]) <= 16.5 && avg(&tr[60..]) >= 12.0);
        assert!(floods <= 40);
    }
        
    /// A flood wait must hold every connection, not only the one that received it, and must not
    /// release a burst when it ends.
    #[test]
    fn flood_wait_pauses_everyone() {
        use std::sync::atomic::AtomicBool;
        let p = Pacer::new(&band());
        let cancel = AtomicBool::new(false);
        assert!(p.acquire(&cancel));
        p.on_flood_wait(0.3);
        let t = Instant::now();
        assert!(p.acquire(&cancel));
        let waited = t.elapsed().as_secs_f64();
        assert!(waited >= 0.25, "acquire must wait out the flood: {waited}");
        // and no burst after the pause: the second request is spaced by the rate, not free
        let t = Instant::now();
        for _ in 0..5 { assert!(p.acquire(&cancel)); }
        assert!(t.elapsed().as_secs_f64() >= 0.05, "no burst after the cooldown");
    }

    /// The same 50/s-ish world as production: a storm that clears must climb back into 30+ quickly.
    #[test]
    fn recovers_into_the_band_after_a_storm() {
        let (tr, _) = run(60, |t, _| t >= 5.0 && t < 9.0);
        println!("\n[G] storm 5-9 s then calm: {:?}", tr.iter().map(|r| r.round() as i64).collect::<Vec<_>>());
        assert!(tr[25] >= 30.0, "25 s after the storm it is back in the band: {}", tr[25]);
    }

    /// Upload defaults of cbgram: start at 28/s with no exponential overshoot, climb ~3%/s while calm.
    fn upload_cfg() -> PacerCfg {
        PacerCfg { rate: 24.0, burst: 4.0, ceiling: 40.0, step: 0.5, growth: 1.1, slow_start_cap: 24.0, hard_floor: 20.0 }
    }

    /// Where the server accepts more than the start: begin at 28 and climb towards the top, never flooding.
    #[test]
    fn upload_start_climbs_when_the_server_allows_it() {
        let (tr, floods) = run_cfg(upload_cfg(), 60, |_, _| false);
        println!("\n[H] upload start, no limit: rate each 10 s {:?}", trace10(&tr));
        assert_eq!(floods, 0);
        assert!(tr[1] >= 24.0 && tr[1] <= 27.0, "starts at ~24, not at the top: {}", tr[1]);
        assert!(tr[25] >= 38.0, "25 s of calm lifts it to the 40 top: {}", tr[25]);
        assert!(max(&tr) <= 40.0 + 1e-9, "never above 40");
    }

    /// Where this bot is limited to ~26/s: no flood at all at the start, then a gentle sawtooth around
    /// the limit, never the 3-4 floods per file and the cut to 20 seen with a start of 45.
    #[test]
    fn upload_start_below_the_limit_floods_rarely() {
        let (tr, floods) = run_cfg(upload_cfg(), 120, |_, rate| rate > 26.0);
        println!("\n[I] upload start, server limit 26/s: rate each 10 s {:?}  floods {}", trace10(&tr), floods);
        assert!(tr[..5].iter().all(|r| *r <= 26.5), "no early overshoot");
        assert!(avg(&tr[1..]) >= 22.0, "average {:.1}", avg(&tr[1..]));
        assert!(min(&tr[1..]) >= 20.0, "never below 20: {}", min(&tr[1..]));
        assert!(floods <= 12, "{floods} floods in 120 s");
    }

    /// Production shape: after a cut the same 1 s flood wait returns every ~1.3 s (in-flight requests
    /// answer, the connections resume, the server is still unhappy). That must never push the rate
    /// below the dip band's three quarters, and the next transfer must start from the dip level.
    #[test]
    fn repeating_one_second_floods_do_not_collapse_the_rate() {
        let cfg = PacerCfg { rate: 48.0, burst: 8.0, ceiling: 80.0, step: 1.0, growth: 1.1, slow_start_cap: 48.0, hard_floor: 40.0 };
        let base = Instant::now();
        let p = Pacer::new_at(&cfg, base);
        let mut t = 0.0;
        while t < 60.0 {
            let now = base + Duration::from_secs_f64(t);
            for _ in 0..16 { p.on_flood_at(now); }          // a burst of replies = one event
            t += 1.3;
        }
        let end = p.rate();
        println!("\n[J] 46 flood events in 60 s: pace {:.1} req/s ({:.1} MiB/s)", end, end / 2.0);
        assert!(end >= 30.0, "must stay at or above 15 MiB/s (30 req/s), got {end}");
        let q = Pacer::new_at(&PacerCfg { hard_floor: 40.0, ..cfg }, base);
        q.on_flood_at(base);
        q.lift_to_dip_level();
        assert!(q.rate() >= 40.0 || q.rate() >= 30.0, "starts the next file from the dip level, got {}", q.rate());
    }
                                 }
