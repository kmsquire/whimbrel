//! Every kind of check whimbrel has, and `alerting`, which it adds itself when a host has
//! channels. `docs/config.md` describes each kind's table.

pub(crate) mod alerting;
pub mod command;
pub mod disk;
pub mod file;
pub mod journald;
pub mod result_file;
pub mod secrets;

use crate::check::Kind;

/// Every kind a config can name.
pub const KINDS: &[Kind] = &[
    disk::KIND,
    file::KIND,
    secrets::KIND,
    journald::KIND,
    command::KIND,
    result_file::KIND,
];
