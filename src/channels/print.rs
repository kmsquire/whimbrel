//! Print, which writes to stdout and stands in for every channel in a dry run.

use serde::Deserialize;

use super::Kind;
use crate::alert::Alert;
use crate::config::from_table;
use crate::ledger::{Channel, Form};

/// ```toml
/// [[channel]]
/// kind = "print"
/// ```
pub const KIND: Kind = Kind {
    name: "print",
    secret_url: None,
    build: |table, _| Ok(Box::new(from_table::<Print>(table)?)),
};

/// Writes to stdout and always succeeds. A config can use it to try a host's checks out; a dry
/// run puts one in place of each real channel, with its name and form and a heading.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Print {
    #[serde(default = "print")]
    pub name: String,
    #[serde(skip)]
    pub form: Form,
    /// Printed above each message: "slack would be sent".
    #[serde(skip)]
    pub heading: Option<String>,
}

fn print() -> String {
    "print".into()
}

impl Print {
    /// The dry run's stand-in for `channel`.
    pub fn instead_of(channel: &dyn Channel) -> Self {
        Print {
            name: channel.name().to_string(),
            form: channel.form(),
            heading: Some(format!("{} would be sent", channel.name())),
        }
    }
}

impl Channel for Print {
    fn name(&self) -> &str {
        &self.name
    }

    fn form(&self) -> Form {
        self.form
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let text = match self.form {
            Form::Short => &alert.short,
            Form::Full => &alert.full,
        };
        match &self.heading {
            Some(h) => println!("\n{h}:\n{text}"),
            None => println!("{text}"),
        }
        Ok(())
    }
}
