package de.netresearch.jira.mfa.ao;

import net.java.ao.Entity;
import net.java.ao.Preload;
import net.java.ao.schema.Indexed;
import net.java.ao.schema.NotNull;
import net.java.ao.schema.StringLength;
import net.java.ao.schema.Table;
import net.java.ao.schema.Unique;

/** Per-user MFA state, keyed by the immutable Jira user key. */
@Preload
@Table("USER_STATE")
public interface MfaUser extends Entity {
    @NotNull
    @Unique
    @Indexed
    String getUserKey();

    void setUserKey(String userKey);

    /** First time the user was seen by the plugin (epoch millis); start of the grace period. */
    long getFirstSeen();

    void setFirstSeen(long firstSeen);

    /** AES-GCM encrypted TOTP secret, null when TOTP is not enrolled. */
    @StringLength(StringLength.UNLIMITED)
    String getTotpSecret();

    void setTotpSecret(String totpSecret);

    long getTotpLastStep();

    void setTotpLastStep(long step);

    /** Random WebAuthn user handle (base64url), created on first passkey registration. */
    @Indexed
    String getUserHandle();

    void setUserHandle(String userHandle);
}
