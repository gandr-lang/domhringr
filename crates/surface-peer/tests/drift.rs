//! The drift check's consumer-visible contract, exercised as processes: a
//! concepts tree opened on a state directory is checked against a public
//! checkout and a vault, two throwaway git repositories whose commits the test
//! makes with a fixed author, committer and date, so the vault's commit ids
//! are the same on every run. `drift` names each finding by its anchor, in
//! anchor order, and says nothing once the pair agrees.

#[cfg(test)]
mod tests
{
    use core::time::Duration;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Command;
    use std::process::Output;
    use std::process::Stdio;
    use std::time::Instant;

    /// How long one command may run.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// How often a running command is polled for its exit.
    const POLL: Duration = Duration::from_millis(20);

    /// The vault's first commit: four pages.
    const FIRST: &str = "2d907719dbbef0f62acd9433327d33c62e517ee5";

    /// The vault's second commit: the drifted page rewritten, the missing page
    /// deleted.
    const SECOND: &str = "f683fd5a75856f51a406111b3069bec046687b85";

    /// The vault's third commit: the missing page restored, the unbound
    /// concept's page added.
    const THIRD: &str = "acfb232ab16370cefc3d55448ed150d1e48ee0a9";

    /// The exit status of a `drift` that reported a finding.
    const DRIFTED: i32 = 3_i32;

    /// `command`, run in an environment of `PATH` alone, with git reading no
    /// configuration but the repository's own.
    ///
    /// # Specification
    /// trivial.
    fn isolated(command: &mut Command) -> &mut Command
    {
        command
            .env_clear()
            .envs(std::env::var_os("PATH").map(|path| ("PATH", path)))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
    }

    /// git in the repository at `directory`, committing as a fixed author and
    /// committer at a fixed date.
    ///
    /// # Specification
    /// trivial.
    fn git(directory: &Path) -> Command
    {
        let mut command = Command::new("git");
        isolated(command.current_dir(directory));
        for role in ["AUTHOR", "COMMITTER"] {
            command
                .env(format!("GIT_{role}_NAME"), "Fixture")
                .env(format!("GIT_{role}_EMAIL"), "fixture@example.test")
                .env(format!("GIT_{role}_DATE"), "2026-01-01T00:00:00+0000");
        }
        command
    }

    /// The peer binary on the state directory `state`.
    ///
    /// # Specification
    /// trivial.
    fn peer(state: &Path) -> Command
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_domhringr-peer"));
        isolated(command.arg("--state").arg(state));
        command
    }

    /// Run `command` to completion and return its output.
    ///
    /// # Specification
    /// - ensures: the command exited within [`DEADLINE`].
    /// - panics: when it cannot start or outlives the deadline (it is killed
    ///   first).
    fn output(command: &mut Command) -> Output
    {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > DEADLINE {
                child.kill().unwrap();
                panic!("{command:?} outlived {DEADLINE:?}");
            }
            std::thread::sleep(POLL);
        }
        child.wait_with_output().unwrap()
    }

    /// Run `command`, which must succeed, and return what it printed.
    ///
    /// # Specification
    /// - ensures: the command exited 0 within [`DEADLINE`].
    /// - panics: as [`output`], or when it exits non-zero (its standard error
    ///   is shown) or prints anything but UTF-8.
    fn finish(command: &mut Command) -> String
    {
        let output = output(command);
        assert!(
            output.status.success(),
            "{command:?}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    /// Commit everything in the repository at `directory` and return the
    /// commit's id.
    ///
    /// # Specification
    /// - panics: as [`finish`].
    fn commit(directory: &Path) -> String
    {
        finish(git(directory).args(["add", "--all"]));
        finish(git(directory).args(["commit", "--quiet", "--message", "fixture"]));
        finish(git(directory).args(["rev-parse", "HEAD"]))
            .trim_end()
            .to_owned()
    }

    /// Write `text` to the file at `file` in `directory`, making its parent
    /// directory.
    ///
    /// # Specification
    /// - panics: when the file cannot be written.
    fn write(
        directory: &Path,
        file: &OsStr,
        text: &OsStr,
    )
    {
        let path = directory.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text.as_encoded_bytes()).unwrap();
    }

    /// `drift` naming the tree whose anchor is `tree` on `state`, with `public`
    /// and `vault` its checkouts.
    ///
    /// # Specification
    /// trivial.
    fn drift(
        state: &Path,
        (public, vault): (&Path, &Path),
        tree: &OsStr,
    ) -> Command
    {
        let mut command = peer(state);
        command
            .arg("drift")
            .arg("--public")
            .arg(public)
            .arg("--vault")
            .arg(vault)
            .arg(tree);
        command
    }

    /// `drift` names each finding of a concepts tree against a public checkout
    /// and a vault in anchor order, and is silent once the pair agrees.
    ///
    /// # Specification
    /// - ensures: the vault's first commit holds four pages, each bound by a
    ///   concept of a tree opened on the state directory: `consistent`,
    ///   `drifted`, `missing` and `orphaned`; its second rewrites the drifted
    ///   page and deletes the missing one. The public checkout cites
    ///   `consistent` and `drifted` in its README, and `missing` and
    ///   `notes/unbound`, which nothing binds, in a guide. `drift` prints
    ///   exactly `drifted`, `missing` and `orphaned` at their pages at the
    ///   first commit and `unbound` at the guide's line 4, in anchor order,
    ///   writes nothing to standard error and exits 3; with `GIT_DIR`,
    ///   `GIT_WORK_TREE` and `GIT_INDEX_FILE` naming the vault, as inside a
    ///   vault hook, it prints the same. Once the drifted page is rebound at
    ///   the second commit, a third restores the missing page and adds the page
    ///   `notes/unbound` is then bound to, and the README cites `orphaned`,
    ///   `drift` prints nothing and exits 0. Each vault commit has its pinned
    ///   id.
    /// - panics: on any contract violation.
    #[test]
    fn drift_names_each_finding_and_is_silent_on_a_consistent_pair()
    {
        let root = tempfile::tempdir().unwrap();
        let (state, public, vault) = (
            root.path().join("state"),
            root.path().join("public"),
            root.path().join("vault"),
        );
        let checkouts = (public.as_path(), vault.as_path());
        for checkout in [&public, &vault] {
            std::fs::create_dir_all(checkout).unwrap();
            finish(git(checkout).args(["init", "--quiet"]));
        }
        let page = |name: &str, text: &str| {
            write(
                &vault,
                OsStr::new(&format!("pages/{name} page.md")),
                OsStr::new(text),
            );
        };
        page("Consistent", "# Consistent\n\nUnchanged throughout.\n");
        page("Drifted", "# Drifted\n\nThe first draft.\n");
        page("Missing", "# Missing\n\nDeleted, then restored.\n");
        page("Orphaned", "# Orphaned\n\nCited nowhere at first.\n");
        let first = commit(&vault);
        assert_eq!(first, FIRST, "the vault's first commit has its pinned id");

        let tree = finish(peer(&state).arg("open")).trim_end().to_owned();
        let bind = |concept: &str, datum: &str| {
            let bound =
                finish(peer(&state).args(["bind", &format!("{tree}{concept}"), "datum", datum]));
            assert_eq!(bound.lines().count(), 1, "a bind prints its commit id");
        };
        for concept in ["Consistent", "Drifted", "Missing", "Orphaned"] {
            bind(
                &concept.to_lowercase(),
                &format!("vault:pages/{concept} page.md@{first}"),
            );
        }

        page("Drifted", "# Drifted\n\nThe second draft.\n");
        std::fs::remove_file(vault.join("pages/Missing page.md")).unwrap();
        let second = commit(&vault);
        assert_eq!(
            second, SECOND,
            "the vault's second commit has its pinned id"
        );

        let readme = format!(
            "# Fixture\n\nThe consistent concept is `{tree}consistent`.\n\nSee <{tree}drifted> for the one that drifts.\n"
        );
        write(&public, OsStr::new("README.md"), OsStr::new(&readme));
        write(
            &public,
            OsStr::new("docs/guide.md"),
            OsStr::new(&format!(
                "A guide to the concepts.\nRead [the missing page]({tree}missing) first.\nThen the rest.\nLast comes {tree}notes/unbound.\n"
            )),
        );
        let _cited = commit(&public);

        let expected = [
            format!("drifted {tree}drifted pages/Drifted page.md@{first}"),
            format!("missing {tree}missing pages/Missing page.md@{first}"),
            format!("unbound {tree}notes/unbound docs/guide.md:4"),
            format!("orphaned {tree}orphaned pages/Orphaned page.md@{first}"),
        ]
        .map(|line| format!("{line}\n"))
        .concat();
        let anchored = OsStr::new(&tree);
        let hooked = format!("{}", vault.join(".git").display());
        for (run, case) in [
            (drift(&state, checkouts, anchored), "run plainly"),
            (
                {
                    let mut command = drift(&state, checkouts, anchored);
                    command
                        .env("GIT_DIR", &hooked)
                        .env("GIT_WORK_TREE", &vault)
                        .env("GIT_INDEX_FILE", vault.join(".git/index"));
                    command
                },
                "run with the environment naming the vault",
            ),
        ] {
            let mut run = run;
            let drifted = output(&mut run);
            assert_eq!(
                String::from_utf8(drifted.stdout).unwrap(),
                expected,
                "drift, {case}, prints exactly its four findings in anchor order"
            );
            assert!(
                drifted.stderr.is_empty(),
                "drift, {case}, reports findings on standard output alone: {}",
                String::from_utf8_lossy(&drifted.stderr)
            );
            assert_eq!(
                drifted.status.code(),
                Some(DRIFTED),
                "drift, {case}, exits 3 on a finding"
            );
        }

        bind("drifted", &format!("vault:pages/Drifted page.md@{second}"));
        page("Missing", "# Missing\n\nDeleted, then restored.\n");
        page("Unbound", "# Unbound\n\nBound last.\n");
        let third = commit(&vault);
        assert_eq!(third, THIRD, "the vault's third commit has its pinned id");
        bind(
            "notes/unbound",
            &format!("vault:pages/Unbound page.md@{third}"),
        );
        write(
            &public,
            OsStr::new("README.md"),
            OsStr::new(&format!("{readme}\nAnd {tree}orphaned, cited at last.\n")),
        );
        let _cited = commit(&public);

        let agreed = output(&mut drift(&state, checkouts, anchored));
        assert!(
            agreed.stdout.is_empty() && agreed.stderr.is_empty(),
            "a consistent pair prints nothing: {}{}",
            String::from_utf8_lossy(&agreed.stdout),
            String::from_utf8_lossy(&agreed.stderr)
        );
        assert_eq!(
            agreed.status.code(),
            Some(0_i32),
            "a consistent pair exits zero"
        );
    }
}
