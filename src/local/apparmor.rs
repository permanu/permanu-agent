//! The agent doctor's `buildkit_apparmor` check (agent-protocol.md 8,
//! contracts v1.1.8/v1.1.9, D-066 #5, D-067 #6): whether rootless BuildKit
//! may run here, and if not, why and how to fix it. The runner enforces the
//! same rule before every start of `permanu-buildkitd@` (its `diagnose`
//! check of the same name); this reading only explains it on the server.

use std::path::Path;

use serde_json::{json, Value};

/// `Y` when AppArmor is enabled on the running kernel.
pub const ENABLED_PATH: &str = "/sys/module/apparmor/parameters/enabled";
/// The loaded profiles, one `name (mode)` per line.
pub const PROFILES_PATH: &str = "/sys/kernel/security/apparmor/profiles";
/// The line of the BuildKit profile in enforce mode.
const PROFILE_LINE: &str = "permanu-buildkitd (enforce)";

/// The outcome of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// AppArmor is enabled and the profile is loaded in enforce mode.
    Loaded,
    /// Server builds are unavailable (`buildkit_unavailable`).
    Absent,
    /// The profile list could not be read (the doctor is not root).
    Unknown,
}

/// Reads `enabled` and `profiles` and returns the outcome with its JSON
/// report: `status` (`loaded` | `absent` | `unknown`), `cause`, `detail` and
/// `fix`.
pub fn buildkit_apparmor(enabled: &Path, profiles: &Path) -> (Outcome, Value) {
    let on = std::fs::read_to_string(enabled).is_ok_and(|text| text.trim() == "Y");
    if !on {
        return (
            Outcome::Absent,
            json!({
                "status": "absent",
                "cause": "apparmor_disabled",
                "detail": "AppArmor is not enabled on this kernel, so on-server builds \
                           (rootless BuildKit) do not run here (buildkit_unavailable).",
                "fix": "Boot a kernel with AppArmor enabled (apparmor=1 security=apparmor), \
                        then re-run the Permanu installer to load /etc/apparmor.d/permanu-buildkitd.",
            }),
        );
    }
    let Ok(list) = std::fs::read_to_string(profiles) else {
        return (
            Outcome::Unknown,
            json!({
                "status": "unknown",
                "cause": "profiles_unreadable",
                "detail": "AppArmor is enabled, but the loaded profiles could not be read.",
                "fix": "Run permanu-agent doctor as root to check the permanu-buildkitd profile.",
            }),
        );
    };
    if list.lines().any(|line| line.trim() == PROFILE_LINE) {
        return (
            Outcome::Loaded,
            json!({
                "status": "loaded",
                "cause": null,
                "detail": "AppArmor is enabled and the permanu-buildkitd profile is loaded in enforce mode.",
                "fix": null,
            }),
        );
    }
    (
        Outcome::Absent,
        json!({
            "status": "absent",
            "cause": "profile_not_loaded",
            "detail": "AppArmor is enabled, but the permanu-buildkitd profile is not loaded in enforce \
                       mode, so on-server builds do not run here (buildkit_unavailable).",
            "fix": "Re-run the Permanu installer to load /etc/apparmor.d/permanu-buildkitd \
                    (or: apparmor_parser -r /etc/apparmor.d/permanu-buildkitd).",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permanu-agent-apparmor-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_check_names_the_cause_and_the_fix() {
        let d = dir("check");
        let enabled = d.join("enabled");
        let profiles = d.join("profiles");

        // No AppArmor module at all (the files are missing).
        let (outcome, report) = buildkit_apparmor(&enabled, &profiles);
        assert_eq!(outcome, Outcome::Absent);
        assert_eq!(report["cause"], "apparmor_disabled");

        std::fs::write(&enabled, "N\n").unwrap();
        let (outcome, report) = buildkit_apparmor(&enabled, &profiles);
        assert_eq!(outcome, Outcome::Absent);
        assert_eq!(report["cause"], "apparmor_disabled");
        assert!(report["fix"].as_str().unwrap().contains("installer"));

        std::fs::write(&enabled, "Y\n").unwrap();
        let (outcome, report) = buildkit_apparmor(&enabled, &profiles);
        assert_eq!(outcome, Outcome::Unknown);
        assert_eq!(report["cause"], "profiles_unreadable");

        // Loaded in complain mode is not enough.
        std::fs::write(
            &profiles,
            "docker-default (enforce)\npermanu-buildkitd (complain)\n",
        )
        .unwrap();
        let (outcome, report) = buildkit_apparmor(&enabled, &profiles);
        assert_eq!(outcome, Outcome::Absent);
        assert_eq!(report["cause"], "profile_not_loaded");
        assert_eq!(report["status"], "absent");

        std::fs::write(
            &profiles,
            "docker-default (enforce)\npermanu-buildkitd (enforce)\n",
        )
        .unwrap();
        let (outcome, report) = buildkit_apparmor(&enabled, &profiles);
        assert_eq!(outcome, Outcome::Loaded);
        assert_eq!(report["status"], "loaded");
        assert!(report["fix"].is_null());
        let _ = std::fs::remove_dir_all(&d);
    }
}
