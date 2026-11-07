package de.netresearch.jira.mfa.core;

import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;

/**
 * Whether a request authenticated with HTTP Basic (username and password)
 * may pass. Password-only REST access bypasses the second factor, so it ends
 * when the second factor becomes binding for the user:
 *
 * <ul>
 *   <li>allow-listed users (service accounts) and the global ALLOW policy: always allowed;</li>
 *   <li>users who need no second factor: allowed;</li>
 *   <li>enforced users without a factor during their grace period: allowed, so
 *   existing scripts keep working while people enrol;</li>
 *   <li>users with a factor: refused, because accepting the password alone
 *   would void the factor they set up, and a verified session can create a
 *   personal access token;</li>
 *   <li>enforced users whose grace period has expired: refused.</li>
 * </ul>
 */
public final class BasicAuthRule {
    private BasicAuthRule() {
    }

    public static boolean allows(MfaSettings settings, String username, Requirement requirement) {
        if (settings.isBasicAuthAllowedFor(username)) {
            return true;
        }
        switch (requirement) {
            case NONE:
                return true;
            case ENROL_OPTIONAL:
                return true;
            case ENROL_REQUIRED:
                return false;
            case VERIFY:
                return false;
            default:
                return false;
        }
    }
}
