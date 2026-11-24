use std::process::ExitCode;

fn main() -> ExitCode {
    whimbrel::run(
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::env::args().skip(1),
    )
}
