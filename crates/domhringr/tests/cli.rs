//! The driver binary's consumer-visible contract, exercised as a process.

#[cfg(test)]
mod tests
{
    /// The driver answers with its version on standard output and exits 0.
    ///
    /// # Specification
    /// - ensures: the built binary exits 0; standard output is exactly one line
    ///   naming `domhringr` and the package version; standard error is empty.
    /// - panics: on any contract violation.
    #[test]
    fn driver_reports_its_version()
    {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_domhringr"))
            .output()
            .unwrap_or_else(|error| panic!("running the driver: {error}"));
        assert!(output.status.success(), "exit status: {}", output.status);
        let stdout =
            String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("stdout: {error}"));
        assert_eq!(
            stdout,
            format!(
                "domhringr {}: component management lands with the first signed release artifacts\n",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert!(
            output.stderr.is_empty(),
            "stderr: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
