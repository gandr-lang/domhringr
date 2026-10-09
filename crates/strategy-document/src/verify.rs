//! Verifiers: a playbook step's program, run as a process on the task's
//! state.
//!
//! A verifier runs its command with its arguments, in the task's state
//! directory, with no standard input, and its standard output and standard
//! error written into one pipe, so its output is one stream in the order the
//! process wrote it. The run is that output and how the process ended — the
//! exit code, or the signal that ended it ([`Status`]) — never a pass or a
//! fail: what a code means is the verifier's to say. The caller commits the
//! output as evidence and records its name.

use alloc::string::String;
use alloc::vec::Vec;
use std::io::Read as _;
use std::path::Path;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;

use domhringr_record_tree::Code;
use domhringr_record_tree::Content;
use domhringr_record_tree::Status;

use crate::document::Key;
use crate::document::Keys;
use crate::document::Refusal;
use crate::document::Slot;
use crate::document::Value;

/// A step's verifier: the program run and its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verifier
{
    /// The program: a path, or a name looked up on `PATH`.
    command: String,
    /// Its arguments, in order.
    arguments: Vec<String>,
}

impl Verifier
{
    /// Read a verifier from its table.
    ///
    /// # Specification
    /// - ensures: the command and the arguments in order, none when `args` is
    ///   absent.
    /// - fails: as the playbook's parser states for a verifier: an unknown
    ///   field, then a missing, mistyped or empty `command`, then `args` that
    ///   is no array of strings.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: the table is no verifier.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the playbook's parser.
    /// - witness: `playbook::tests::a_playbook_reads_its_steps_in_order`
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    pub(crate) fn read(value: Value<'_>) -> Result<Self, Refusal>
    {
        let mut table = value.table(Keys(&["command", "args"]))?;
        let command = table.require(Key("command"))?.filled()?;
        let mut arguments = Vec::new();
        if let Slot::Given(listed) = table.take(Key("args")) {
            for argument in listed.array()? {
                arguments.push(argument.text()?);
            }
        }
        Ok(Self { command, arguments })
    }

    /// The program.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn command(&self) -> &String
    {
        &self.command
    }

    /// The arguments, in order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn arguments(&self) -> &[String]
    {
        &self.arguments
    }

    /// Run the verifier in `directory` and read how it ended.
    ///
    /// # Specification
    /// - ensures: runs the command with its arguments, `directory` as its
    ///   working directory, standard input closed, and standard output and
    ///   standard error into one pipe; waits for it to end; returns everything
    ///   the process wrote, in the order written, and its exit code, or the
    ///   signal that ended it.
    /// - fails: [`VerifyError::Pipe`] when the pipe cannot be made,
    ///   [`VerifyError::Spawn`] when the command cannot be started — no such
    ///   program, or `directory` missing — [`VerifyError::Read`] when the
    ///   output cannot be read, [`VerifyError::Wait`] when the process cannot
    ///   be waited on, and [`VerifyError::Unended`] for a status that names
    ///   neither a code nor a signal.
    /// - panics: none.
    /// - intension: the output is read to its end before the process is waited
    ///   on, so a verifier writing more than a pipe holds does not block; a
    ///   process the verifier leaves holding the pipe holds the run open until
    ///   it exits.
    ///
    /// # Errors
    /// - [`VerifyError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a real shell verifier writing to both streams in a
    ///   state directory is run, its output compared with the bytes it wrote
    ///   there and its exit code read; a failing exit code is read as the code,
    ///   a process killing itself as its signal, and a missing program is
    ///   refused as unspawned.
    /// - witness: `verify::tests::a_verifier_runs_in_the_state_directory_and_reads_its_status`
    #[inline]
    pub fn run(
        &self,
        directory: &Path,
    ) -> Result<Run, VerifyError>
    {
        let (mut reader, writer) = std::io::pipe().map_err(VerifyError::Pipe)?;
        let errors = writer.try_clone().map_err(VerifyError::Pipe)?;
        let mut command = Command::new(&self.command);
        let _configured = command
            .args(&self.arguments)
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(errors);
        let spawned = command.spawn();
        // The command holds the pipe's writing ends until dropped: the read
        // below sees the end of the output only once the process alone does.
        drop(command);
        let mut child = spawned.map_err(|source| VerifyError::Spawn {
            command: self.command.clone(),
            source,
        })?;
        let mut output = Vec::new();
        let _length = reader.read_to_end(&mut output).map_err(VerifyError::Read)?;
        let ended = child.wait().map_err(VerifyError::Wait)?;
        let status = status(ended)?;
        Ok(Run {
            output: Content::from(output),
            status,
        })
    }
}

/// How a process's exit status reads as a record's [`Status`].
///
/// # Specification
/// - ensures: an exit code reads as [`Status::Exited`]; on Unix, a process
///   ended by a signal reads as [`Status::Signalled`].
/// - fails: [`VerifyError::Unended`] for a status naming neither.
/// - panics: none.
///
/// # Errors
/// - [`VerifyError::Unended`]: the status names neither a code nor a signal.
///
/// # Adequacy
/// - hypothesis: L3 — a process exiting 0 and 3 and one killing itself with
///   `SIGKILL` are read as such.
/// - witness: `verify::tests::a_verifier_runs_in_the_state_directory_and_reads_its_status`
fn status(ended: ExitStatus) -> Result<Status, VerifyError>
{
    if let Some(code) = ended.code() {
        return Ok(Status::Exited(Code::from(code)));
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = ended.signal() {
            return Ok(Status::Signalled(domhringr_record_tree::Signal::from(
                signal,
            )));
        }
    }
    Err(VerifyError::Unended)
}

/// What a verifier's run left: its output and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run
{
    /// What the process wrote to its output and error, in the order written.
    output: Content,
    /// How the process ended.
    status: Status,
}

impl Run
{
    /// The process's output.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn output(&self) -> &Content
    {
        &self.output
    }

    /// How the process ended.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn status(&self) -> Status
    {
        self.status
    }
}

/// Why a verifier did not run to its end.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError
{
    /// The output's pipe cannot be made.
    #[error("cannot make the verifier's output pipe")]
    Pipe(#[source] std::io::Error),
    /// The command cannot be started.
    #[error("cannot run the verifier {command:?}")]
    Spawn
    {
        /// The program.
        command: String,
        /// Why it did not start.
        #[source]
        source: std::io::Error,
    },
    /// The output cannot be read.
    #[error("cannot read the verifier's output")]
    Read(#[source] std::io::Error),
    /// The process cannot be waited on.
    #[error("cannot wait for the verifier")]
    Wait(#[source] std::io::Error),
    /// The process ended with neither an exit code nor a signal.
    #[error("the verifier ended with neither an exit code nor a signal")]
    Unended,
}

#[cfg(test)]
mod tests
{
    use domhringr_record_tree::Code;
    use domhringr_record_tree::Content;
    use domhringr_record_tree::Signal;
    use domhringr_record_tree::Status;

    use super::Verifier;
    use super::VerifyError;

    /// The verifier running `script` under `sh`.
    ///
    /// # Specification
    /// trivial.
    fn shell(script: String) -> Verifier
    {
        Verifier {
            command: "sh".into(),
            arguments: vec!["-c".into(), script],
        }
    }

    #[test]
    fn a_verifier_runs_in_the_state_directory_and_reads_its_status()
    {
        let state = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("change.diff"), "+ one line\n").unwrap();
        let run = shell("cat change.diff; echo to-error >&2; exit 3".into())
            .run(state.path())
            .unwrap();
        assert_eq!(
            run.output(),
            &Content::from(b"+ one line\nto-error\n".to_vec()),
            "the output is both streams in the order written, read in the state directory"
        );
        assert_eq!(
            run.status(),
            Status::Exited(Code::from(3_i32)),
            "a failing code is read as it is"
        );
        let run = shell("true".into()).run(state.path()).unwrap();
        assert_eq!(
            (run.output(), run.status()),
            (
                &Content::from(Vec::new()),
                Status::Exited(Code::from(0_i32))
            ),
            "a silent passing verifier"
        );
        assert_eq!(
            shell("kill -9 $$".into())
                .run(state.path())
                .unwrap()
                .status(),
            Status::Signalled(Signal::from(9_i32)),
            "a process ended by a signal is read as the signal"
        );
        let missing = Verifier {
            command: "domhringr-no-such-verifier".into(),
            arguments: Vec::new(),
        };
        assert!(
            matches!(missing.run(state.path()), Err(VerifyError::Spawn { .. })),
            "a program that does not exist does not run"
        );
    }
}
