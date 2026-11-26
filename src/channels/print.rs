//! Print, which writes each alert to stdout.

use serde::Deserialize;

use super::Kind;
use crate::alert::Alert;
use crate::config::from_table;
use crate::ledger::Channel;

/// ```toml
/// [[channel]]
/// kind = "print"
/// ```
pub const KIND: Kind = Kind {
    name: "print",
    secret_url: None,
    build: |table, _| Ok(Box::new(from_table::<Print>(table)?)),
};

/// Writes the full form to stdout and always succeeds. A config can use it to try a host's checks
/// out.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Print {
    #[serde(default = "print")]
    pub name: String,
}

fn print() -> String {
    "print".into()
}

impl Channel for Print {
    fn name(&self) -> &str {
        &self.name
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        println!("{}", alert.full);
        Ok(())
    }
}
