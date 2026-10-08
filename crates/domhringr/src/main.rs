//! `domhringr`: the driver for the domhringr factory toolchain.
//!
//! The driver fetches, verifies, and installs the factory's components from
//! signed release artifacts, by `(component, version, target)`. At `0.0.0` it
//! claims the name and reports its version.

// The opt-in quenchant lints: absence named by `Maybe` in signatures and in
// fields outside wire form, arithmetic on nominal types. Selected here because
// Dylint's `-D` cannot reach rustc through `cargo dylint`; see
// `.config/mise/tasks/mise-tasks-check.toml`.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]

use std::io::Write as _;
use std::process::ExitCode;

/// The one line the driver writes at `0.0.0`.
const BANNER: &str = concat!(
    "domhringr ",
    env!("CARGO_PKG_VERSION"),
    ": component management lands with the first signed release artifacts\n"
);

/// Entry point.
///
/// # Specification
/// - ensures: writes [`BANNER`] to standard output and exits 0; arguments are
///   ignored until the driver has commands.
/// - fails: exits 1 when standard output cannot be written.
/// - panics: none.
fn main() -> ExitCode
{
    match std::io::stdout().lock().write_all(BANNER.as_bytes()) {
        | Ok(()) => ExitCode::SUCCESS,
        | Err(_) => ExitCode::FAILURE,
    }
}
