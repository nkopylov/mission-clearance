use chrono::{DateTime, Utc};
use mc_core::vault::RotationPolicy;

/// Determine whether a credential should be rotated based on its policy
/// and the time it was last rotated.
///
/// - `TimeBased`: returns `true` when the elapsed time since `last_rotated`
///   meets or exceeds `interval_days`.
/// - `UsageBased`: stub implementation — always returns `false` because
///   usage counter tracking is not yet implemented.
pub fn should_rotate(policy: &RotationPolicy, last_rotated: &DateTime<Utc>) -> bool {
    match policy {
        RotationPolicy::TimeBased { interval_days } => {
            let elapsed = Utc::now().signed_duration_since(*last_rotated);
            let interval = chrono::Duration::days(i64::from(*interval_days));
            elapsed >= interval
        }
        RotationPolicy::UsageBased { .. } => {
            // Stub: usage-based rotation needs a counter tracking system.
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn time_based_rotation_due() {
        let policy = RotationPolicy::TimeBased { interval_days: 30 };
        let last_rotated = Utc::now() - Duration::days(31);
        assert!(should_rotate(&policy, &last_rotated));
    }

    #[test]
    fn time_based_rotation_not_due() {
        let policy = RotationPolicy::TimeBased { interval_days: 30 };
        let last_rotated = Utc::now() - Duration::days(10);
        assert!(!should_rotate(&policy, &last_rotated));
    }

    #[test]
    fn time_based_rotation_exact_boundary() {
        let policy = RotationPolicy::TimeBased { interval_days: 30 };
        let last_rotated = Utc::now() - Duration::days(30);
        assert!(should_rotate(&policy, &last_rotated));
    }

    #[test]
    fn usage_based_always_false() {
        let policy = RotationPolicy::UsageBased { max_uses: 100 };
        let last_rotated = Utc::now() - Duration::days(365);
        assert!(!should_rotate(&policy, &last_rotated));
    }
}
