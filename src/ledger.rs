//! What each channel was last told, and what it hasn't heard about since.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::alert::{Alert, Frame, News, Why};
use crate::check::{CheckResult, Level};

/// Somewhere an alert goes.
pub trait Channel {
    /// Stable, and unique among a host's channels: the ledger is kept under it.
    fn name(&self) -> &str;
    /// Deliver it, or say why not. The reason is logged, so it must never hold a secret.
    fn send(&mut self, alert: &Alert) -> Result<(), String>;
    /// Which form of an alert it sends: the full one unless it says otherwise.
    fn form(&self) -> Form {
        Form::Full
    }
    /// Whether a send could go through, as far as it can tell without sending: its secrets are
    /// readable and well formed, say. The reason is shown, so it must never hold a secret.
    fn ready(&self) -> Result<(), String> {
        Ok(())
    }
}

/// An alert's two forms: `short` for a phone, `full` with every check's details.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Form {
    Short,
    #[default]
    Full,
}

/// What one channel did this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing new to say.
    Unchanged,
    Sent,
    Failed(String),
}

/// A problem still open this long after a channel was last told is sent again: a day, less a
/// little, so an hourly timer that runs a minute early still reminds on the 24th run, not the 25th.
pub const REMIND_AFTER_SECS: u64 = 24 * 60 * 60 - REMINDER_SLACK_SECS;
const REMINDER_SLACK_SECS: u64 = 10 * 60;

/// Every channel's ledger. New fields take their defaults, so a ledger written by an older
/// version still loads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    version: u32,
    channels: BTreeMap<String, ChannelLedger>,
    /// Set when the ledger was lost; every channel is told so, and what's open, once.
    lost_track: bool,
}

impl Default for State {
    fn default() -> Self {
        State {
            version: 1,
            channels: BTreeMap::new(),
            lost_track: false,
        }
    }
}

/// One channel's: what it was last told and when, and the worst it missed since, by key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct ChannelLedger {
    told: Option<Delivery>,
    unheard: BTreeMap<String, Unheard>,
    /// It hasn't yet been told the ledger was lost.
    lost: bool,
}

/// The last thing that got through.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct Delivery {
    /// Unix seconds.
    at: u64,
    problems: BTreeMap<String, Told>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Told {
    level: Level,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    about: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    count: Option<u64>,
}

/// A problem worse than what the channel was told, seen while nothing got through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Unheard {
    level: Level,
    /// What was wrong, without what to run.
    what: String,
}

/// Two channels share a name, so they'd share a ledger, and one would never be told anything.
#[derive(Debug, PartialEq, Eq)]
pub struct DuplicateChannel(pub String);

impl fmt::Display for DuplicateChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "two channels are named {:?}", self.0)
    }
}

impl std::error::Error for DuplicateChannel {}

impl State {
    /// A fresh ledger in place of one that was lost. Every channel's next message says so and
    /// lists everything open, even if nothing changed; until one gets through it's retried like
    /// any other. A problem that came and went while the ledger was lost is never named, and one
    /// that recovered then gets no all-clear: what it was told is exactly what was lost.
    pub fn lost_track() -> Self {
        State {
            lost_track: true,
            ..State::default()
        }
    }

    /// The channels with a ledger, by name.
    pub fn channels(&self) -> impl Iterator<Item = &str> {
        self.channels.keys().map(String::as_str)
    }
}

/// Tell each channel what changed since it was last told, and record what got through.
///
/// A channel is sent something when the problems now differ from what it was told, by level or
/// fingerprint, or by a count that rose; when something worse than it was told came and went
/// while nothing got through; or when a problem it was told about has been open a day. On a
/// failed send what it was told stays put, so the next run tries again from there. `now` is Unix
/// seconds.
///
/// Delivery is at least once: the caller saves the state after this returns, so a crash between
/// a send and the save sends it again next run.
///
/// Ledgers of channels not passed in are dropped: a channel removed and added back later is told
/// what's wrong then, as a new one would be.
pub fn deliver(
    state: &mut State,
    results: &[CheckResult],
    channels: &mut [&mut dyn Channel],
    frame: &Frame,
    now: u64,
) -> Result<Vec<(String, Outcome)>, DuplicateChannel> {
    let mut names = BTreeSet::new();
    for channel in channels.iter() {
        if !names.insert(channel.name().to_string()) {
            return Err(DuplicateChannel(channel.name().to_string()));
        }
    }
    state.channels.retain(|name, _| names.contains(name));
    // A fingerprint is kept in the ledger, and a check may build it from words it found on the
    // host, a row's name say, so it's redacted like everything else that's kept.
    let results: Vec<CheckResult> = results
        .iter()
        .map(|r| {
            let mut r = r.clone();
            r.finding.fingerprint = r.finding.fingerprint.map(|f| frame.redacted(f));
            r
        })
        .collect();
    let results = &results[..];
    let lost = std::mem::take(&mut state.lost_track);
    let current: Vec<&CheckResult> = results.iter().filter(|r| r.is_problem()).collect();
    Ok(channels
        .iter_mut()
        .map(|channel| {
            let name = channel.name().to_string();
            let ledger = state.channels.entry(name.clone()).or_default();
            ledger.lost |= lost;
            ledger.observe(&current, frame);
            let outcome = match ledger.news(&current, now) {
                None => Outcome::Unchanged,
                Some(news) => match channel.send(&frame.compose(&news)) {
                    Ok(()) => {
                        ledger.delivered(&current, now);
                        Outcome::Sent
                    }
                    // Logged, and a health check copies the log into its own alerts.
                    Err(why) => Outcome::Failed(frame.redacted(why)),
                },
            };
            (name, outcome)
        })
        .collect())
}

impl ChannelLedger {
    fn told_level(&self, key: &str) -> Level {
        self.told
            .as_ref()
            .and_then(|d| d.problems.get(key))
            .map_or(Level::Ok, |t| t.level)
    }

    /// Keep the worst of each problem that's worse than what this channel was told, and lower a
    /// told count to one that fell, so a rise is measured from the last count seen, not sent.
    fn observe(&mut self, current: &[&CheckResult], frame: &Frame) {
        for r in current {
            let told = self.told.as_mut().and_then(|d| d.problems.get_mut(&r.key));
            // Only a count that's there: None sorts below every count.
            if let Some(t) = told
                && r.finding.count.is_some()
                && r.finding.count < t.count
            {
                t.count = r.finding.count;
            }
            if r.finding.level <= self.told_level(&r.key) {
                continue;
            }
            match self.unheard.get(&r.key) {
                Some(u) if u.level > r.finding.level => {}
                _ => {
                    let unheard = Unheard {
                        level: r.finding.level,
                        what: frame.redacted(r.finding.first_what().to_string()),
                    };
                    self.unheard.insert(r.key.clone(), unheard);
                }
            }
        }
    }

    /// What this channel should hear now, if anything.
    fn news<'a>(&self, current: &[&'a CheckResult], now: u64) -> Option<News<'a>> {
        let empty = BTreeMap::new();
        let told = self.told.as_ref().map_or(&empty, |d| &d.problems);
        let level_now = |key: &str| {
            current
                .iter()
                .find(|r| r.key == key)
                .map_or(Level::Ok, |r| r.finding.level)
        };
        let came_and_went: Vec<String> = self
            .unheard
            .iter()
            .filter(|(key, u)| u.level > level_now(key))
            .map(|(_, u)| u.what.clone())
            .collect();
        let differs = current.len() != told.len()
            || current.iter().any(|r| {
                told.get(&r.key).is_none_or(|t| {
                    t.level != r.finding.level
                        || t.fingerprint != r.finding.fingerprint
                        || r.finding.count > t.count
                })
            });
        let why = if self.lost {
            Why::LostTrack
        } else if differs || !came_and_went.is_empty() {
            Why::Changed
        } else if self.told.as_ref().is_some_and(|d| {
            !d.problems.is_empty() && now >= d.at.saturating_add(REMIND_AFTER_SECS)
        }) {
            Why::Reminder
        } else {
            return None;
        };
        let recovered = told
            .iter()
            .filter(|(key, _)| !current.iter().any(|r| &r.key == *key))
            .map(|(_, t)| t.about.clone())
            .collect();
        Some(News {
            why,
            current: current.to_vec(),
            recovered,
            came_and_went,
        })
    }

    fn delivered(&mut self, current: &[&CheckResult], now: u64) {
        let problems = current
            .iter()
            .map(|r| {
                let told = Told {
                    level: r.finding.level,
                    fingerprint: r.finding.fingerprint.clone(),
                    about: r.about.clone(),
                    count: r.finding.count,
                };
                (r.key.clone(), told)
            })
            .collect();
        self.told = Some(Delivery { at: now, problems });
        self.unheard.clear();
        self.lost = false;
    }
}
