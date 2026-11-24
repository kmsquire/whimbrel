//! Whether every channel could send: a webhook file gone missing is otherwise only a line in the
//! log. The core adds this check whenever a host has channels, so the others carry the news.

use crate::check::{At, Check, Configured, Finding};
use crate::ledger::Channel;

/// The key, which no configured check may also use.
pub const KEY: &str = "alerting";

pub(crate) struct Alerting {
    pub channels: Vec<Box<dyn Channel>>,
}

impl Alerting {
    /// Under its own key.
    pub fn configured(channels: Vec<Box<dyn Channel>>) -> Configured {
        Configured {
            key: KEY.into(),
            about: "alerting".into(),
            check: Box::new(Alerting { channels }),
        }
    }
}

impl Check for Alerting {
    /// The channels that can't send are the fingerprint, so another one failing is news.
    fn run(&self, _at: &At) -> Finding {
        let not: Vec<(&str, String)> = self
            .channels
            .iter()
            .filter_map(|c| c.ready().err().map(|why| (c.name(), why)))
            .collect();
        if not.is_empty() {
            return Finding::ok();
        }
        let names: Vec<&str> = not.iter().map(|(n, _)| *n).collect();
        let why: Vec<String> = not.iter().map(|(n, why)| format!("{n}: {why}")).collect();
        Finding::warn()
            .says(format!("Alerts can't get to {}.", why.join("; ")))
            .see_dry_run()
            .fingerprint(names.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Alert;

    struct Fake(&'static str, Result<(), String>);

    impl Channel for Fake {
        fn name(&self) -> &str {
            self.0
        }
        fn send(&mut self, _: &Alert) -> Result<(), String> {
            unreachable!("readiness never sends")
        }
        fn ready(&self) -> Result<(), String> {
            self.1.clone()
        }
    }

    fn alerting(channels: Vec<Fake>) -> Finding {
        let channels = channels
            .into_iter()
            .map(|c| Box::new(c) as Box<dyn Channel>)
            .collect();
        let run = crate::check::Run {
            now: std::time::SystemTime::UNIX_EPOCH,
            host: "h",
            state_dir: std::path::Path::new("/nonexistent"),
            mode: crate::run::Mode::DryRun,
        };
        Alerting { channels }.run(&run.at(KEY, "alerting"))
    }

    #[test]
    fn every_channel_ready_is_ok() {
        assert_eq!(alerting(vec![Fake("a", Ok(()))]), Finding::ok());
    }

    #[test]
    fn the_channels_that_cant_send_are_named_and_are_the_fingerprint() {
        let one = alerting(vec![
            Fake("slack", Err("its webhook file is gone".into())),
            Fake("print", Ok(())),
        ]);
        assert_eq!(
            one,
            Finding::warn()
                .says("Alerts can't get to slack: its webhook file is gone.")
                .see_dry_run()
                .fingerprint("slack")
        );
        let two = alerting(vec![
            Fake("slack", Err("its webhook file is gone".into())),
            Fake("bluebubbles", Err("its password file is gone".into())),
        ]);
        assert_eq!(two.fingerprint.as_deref(), Some("slack,bluebubbles"));
        assert_eq!(
            two.first_what(),
            "Alerts can't get to slack: its webhook file is gone; bluebubbles: its password file \
             is gone."
        );
    }
}
