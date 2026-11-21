//! Asks the system package manager about, and installs, the `antiwire` package.
//!
//! Upgrades go through the distribution's front end (`apt-get`, `dnf`, or
//! `zypper`), so new dependencies are installed with the package. A rollback
//! reinstalls the version that was running before the upgrade, whose
//! dependencies are already present, so it uses `dpkg` or `rpm` directly: they
//! can downgrade without a resolver, and they also repair a package an
//! interrupted upgrade left half-configured.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use semver::Version;

use crate::package::PackageFormat;
use crate::system_program::{require_system_program, system_program};
use crate::UpdateError;

/// The package name in `packaging/linux/nfpm.yaml`.
pub const PACKAGE_NAME: &str = "antiwire";

/// The system package manager, as a trait so the install swap is tested
/// without one.
pub trait PackageInstaller {
    /// The installed version of [`PACKAGE_NAME`], or `None` when it is not
    /// installed.
    ///
    /// # Errors
    ///
    /// When the package database cannot be queried.
    fn installed_version(&self, format: PackageFormat) -> Result<Option<Version>, UpdateError>;

    /// Installs the package file at `package`. `rollback` reinstalls the
    /// version from before an upgrade, which may be older than the one
    /// installed now.
    ///
    /// # Errors
    ///
    /// When the package manager fails.
    fn install(
        &self,
        format: PackageFormat,
        package: &Path,
        rollback: bool,
    ) -> Result<(), UpdateError>;
}

/// Runs the package manager on this machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPackageInstaller;

impl PackageInstaller for SystemPackageInstaller {
    fn installed_version(&self, format: PackageFormat) -> Result<Option<Version>, UpdateError> {
        let query = match format {
            PackageFormat::Deb => {
                Invocation::new("dpkg-query").args(["-W", "-f=${Version}", PACKAGE_NAME])
            }
            PackageFormat::Rpm => {
                Invocation::new("rpm").args(["-q", "--qf", "%{VERSION}", PACKAGE_NAME])
            }
        };
        let output = query.output()?;
        if !output.status.success() {
            return Ok(None);
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        parse_package_version(&raw).map(Some).ok_or_else(|| {
            UpdateError::Service(format!(
                "the package manager reports an unreadable version: {}",
                raw.trim()
            ))
        })
    }

    fn install(
        &self,
        format: PackageFormat,
        package: &Path,
        rollback: bool,
    ) -> Result<(), UpdateError> {
        let invocation = install_invocation(format, package, rollback, &|name| {
            system_program(name).is_some()
        });
        let output = invocation.output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(UpdateError::Service(format!(
            "{} failed ({}): {}",
            invocation.program,
            output.status,
            tail(&String::from_utf8_lossy(&output.stderr))
        )))
    }
}

/// Which format's package owns `daemon_exe`, if any.
///
/// The daemon updates itself only when the package manager installed it. A
/// tarball install or a development build is not owned by a package, and an
/// update there would put a second copy beside it.
#[must_use]
pub fn owner_format(daemon_exe: &Path) -> Option<PackageFormat> {
    let owned = |invocation: Invocation, parse: fn(&str) -> bool| {
        invocation
            .output()
            .ok()
            .filter(|output| output.status.success())
            .is_some_and(|output| parse(&String::from_utf8_lossy(&output.stdout)))
    };
    if system_program("dpkg-query").is_some()
        && owned(
            Invocation::new("dpkg-query").arg("-S").arg(daemon_exe),
            dpkg_search_names_package,
        )
    {
        return Some(PackageFormat::Deb);
    }
    if system_program("rpm").is_some()
        && owned(
            Invocation::new("rpm")
                .args(["-qf", "--qf", "%{NAME}\\n"])
                .arg(daemon_exe),
            |stdout| stdout.lines().any(|line| line.trim() == PACKAGE_NAME),
        )
    {
        return Some(PackageFormat::Rpm);
    }
    None
}

/// `dpkg-query -S` prints `package[, package…]: path`. True when
/// [`PACKAGE_NAME`] is one of the packages.
fn dpkg_search_names_package(stdout: &str) -> bool {
    stdout.lines().any(|line| {
        line.split_once(": ").is_some_and(|(packages, _)| {
            packages
                .split(',')
                .map(|package| package.trim().split(':').next().unwrap_or_default())
                .any(|package| package == PACKAGE_NAME)
        })
    })
}

/// A package version as semver.
///
/// RPM versions cannot contain `-`, so a prerelease such as `0.3.0-beta.1` can
/// appear as `0.3.0~beta.1` or `0.3.0_beta.1`, and Debian versions may carry an
/// epoch (`1:`) or a numeric revision (`-1`). All map back to the release
/// version.
#[must_use]
pub fn parse_package_version(raw: &str) -> Option<Version> {
    let raw = raw.trim();
    let raw = raw.split_once(':').map_or(raw, |(_, rest)| rest);
    let semver = raw.replace(['~', '_'], "-");
    if let Ok(version) = Version::parse(&semver) {
        // A purely numeric "prerelease" is a Debian revision, not a semver one.
        if !version.pre.is_empty() && version.pre.as_str().bytes().all(|b| b.is_ascii_digit()) {
            return Some(Version::new(version.major, version.minor, version.patch));
        }
        return Some(version);
    }
    let (upstream, revision) = semver.rsplit_once('-')?;
    if revision.bytes().all(|byte| byte.is_ascii_digit()) {
        return parse_package_version(upstream);
    }
    None
}

/// One command to run, kept as data so the choice of command is tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub program: &'static str,
    pub args: Vec<OsString>,
    pub env: Vec<(&'static str, &'static str)>,
}

impl Invocation {
    fn new(program: &'static str) -> Self {
        Self {
            program,
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    fn env(mut self, key: &'static str, value: &'static str) -> Self {
        self.env.push((key, value));
        self
    }

    fn output(&self) -> Result<std::process::Output, UpdateError> {
        let program = require_system_program(self.program)
            .map_err(|error| UpdateError::io("find", self.program, error))?;
        Command::new(&program)
            .args(&self.args)
            .envs(self.env.iter().copied())
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| UpdateError::io("run", program, error))
    }
}

/// The command that installs `package`. `available` says whether a program is
/// on this machine.
pub(crate) fn install_invocation(
    format: PackageFormat,
    package: &Path,
    rollback: bool,
    available: &dyn Fn(&str) -> bool,
) -> Invocation {
    match (format, rollback) {
        (PackageFormat::Deb, false) if available("apt-get") => Invocation::new("apt-get")
            .args([
                "install",
                "-y",
                "--allow-downgrades",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
            ])
            .arg(package)
            .env("DEBIAN_FRONTEND", "noninteractive"),
        // dpkg downgrades with a warning, and configures a package that an
        // interrupted install left unpacked.
        (PackageFormat::Deb, _) => Invocation::new("dpkg")
            .args(["-i", "--force-confold"])
            .arg(package),
        (PackageFormat::Rpm, true) => Invocation::new("rpm")
            .args(["-U", "--oldpackage", "--replacepkgs"])
            .arg(package),
        // The package is unsigned; its SHA-256 is in the signed manifest and was
        // checked before this runs, so the front end's own signature check is off.
        (PackageFormat::Rpm, false) if available("dnf") => Invocation::new("dnf")
            .args(["install", "-y", "--nogpgcheck"])
            .arg(package),
        (PackageFormat::Rpm, false) if available("zypper") => Invocation::new("zypper")
            .args(["--non-interactive", "install", "--allow-unsigned-rpm"])
            .arg(package),
        (PackageFormat::Rpm, false) => Invocation::new("rpm").arg("-U").arg(package),
    }
}

/// The end of a command's error output, which is where the reason is.
fn tail(text: &str) -> String {
    const LIMIT: usize = 600;
    let text = text.trim();
    let count = text.chars().count();
    if count <= LIMIT {
        return text.to_owned();
    }
    let skipped: String = text.chars().skip(count - LIMIT).collect();
    format!("…{skipped}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_and_args(invocation: &Invocation) -> (String, Vec<String>) {
        (
            invocation.program.to_owned(),
            invocation
                .args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
        )
    }

    #[test]
    fn parses_package_versions() {
        let v = |text| parse_package_version(text);
        assert_eq!(v("0.3.0"), Some(Version::new(0, 3, 0)));
        assert_eq!(v("0.3.0\n"), Some(Version::new(0, 3, 0)));
        assert_eq!(v("0.3.0-1"), Some(Version::new(0, 3, 0)));
        assert_eq!(v("1:0.3.0-2"), Some(Version::new(0, 3, 0)));
        assert_eq!(v("0.3.0~beta.1"), Version::parse("0.3.0-beta.1").ok());
        assert_eq!(v("0.3.0-beta.1"), Version::parse("0.3.0-beta.1").ok());
        assert_eq!(v("0.3.0_beta.1"), Version::parse("0.3.0-beta.1").ok());
        assert_eq!(v("garbage"), None);
    }

    #[test]
    fn reads_the_owner_from_dpkg_search() {
        assert!(dpkg_search_names_package(
            "antiwire: /usr/bin/antiwire-daemon\n"
        ));
        assert!(dpkg_search_names_package(
            "antiwire:amd64: /usr/bin/antiwire-daemon\n"
        ));
        assert!(dpkg_search_names_package(
            "other, antiwire: /usr/bin/antiwire-daemon\n"
        ));
        assert!(!dpkg_search_names_package(
            "antiwire-tools: /usr/bin/antiwire-daemon\n"
        ));
    }

    #[test]
    fn upgrades_go_through_the_front_end() {
        let package = Path::new("/var/lib/antiwire/updates/verified/0.3.0/a.deb");
        let all = |_: &str| true;
        let none = |_: &str| false;

        let (program, args) = program_and_args(&install_invocation(
            PackageFormat::Deb,
            package,
            false,
            &all,
        ));
        assert_eq!(program, "apt-get");
        assert_eq!(args.first().map(String::as_str), Some("install"));
        assert_eq!(args.last().map(String::as_str), package.to_str());

        let (program, _) = program_and_args(&install_invocation(
            PackageFormat::Deb,
            package,
            false,
            &none,
        ));
        assert_eq!(program, "dpkg");

        let rpm = Path::new("/var/lib/antiwire/updates/verified/0.3.0/a.rpm");
        let only = |wanted: &'static str| move |name: &str| name == wanted;
        let (program, args) = program_and_args(&install_invocation(
            PackageFormat::Rpm,
            rpm,
            false,
            &only("dnf"),
        ));
        assert_eq!(program, "dnf");
        assert!(args.contains(&"--nogpgcheck".to_owned()));
        let (program, args) = program_and_args(&install_invocation(
            PackageFormat::Rpm,
            rpm,
            false,
            &only("zypper"),
        ));
        assert_eq!(program, "zypper");
        assert!(args.contains(&"--allow-unsigned-rpm".to_owned()));
        let (program, _) =
            program_and_args(&install_invocation(PackageFormat::Rpm, rpm, false, &none));
        assert_eq!(program, "rpm");
    }

    #[test]
    fn rollbacks_may_downgrade() {
        let all = |_: &str| true;
        let (program, args) = program_and_args(&install_invocation(
            PackageFormat::Deb,
            Path::new("/x/a.deb"),
            true,
            &all,
        ));
        assert_eq!(program, "dpkg");
        assert_eq!(args[0], "-i");
        let (program, args) = program_and_args(&install_invocation(
            PackageFormat::Rpm,
            Path::new("/x/a.rpm"),
            true,
            &all,
        ));
        assert_eq!(program, "rpm");
        assert!(args.contains(&"--oldpackage".to_owned()));
    }

    #[test]
    fn keeps_the_end_of_long_errors() {
        let long = "x".repeat(700) + "the real reason";
        let kept = tail(&long);
        assert!(kept.ends_with("the real reason"));
        assert!(kept.chars().count() <= 601);
    }
}
