package de.netresearch.jira.mfa.ao;

import net.java.ao.Entity;
import net.java.ao.Preload;
import net.java.ao.schema.Indexed;
import net.java.ao.schema.NotNull;
import net.java.ao.schema.StringLength;
import net.java.ao.schema.Table;

/** A registered WebAuthn credential. */
@Preload
@Table("PASSKEY")
public interface MfaPasskey extends Entity {
    @NotNull
    @Indexed
    String getUserKey();

    void setUserKey(String userKey);

    /**
     * Credential ID, base64url. The longest string column Active Objects can
     * still index (450 characters, about 337 bytes); without the annotation it
     * would be the 255-character default. Longer IDs are refused at registration.
     */
    @NotNull
    @Indexed
    @StringLength(StringLength.MAX_LENGTH)
    String getCredentialId();

    void setCredentialId(String credentialId);

    /** COSE public key, base64url. */
    @NotNull
    @StringLength(StringLength.UNLIMITED)
    String getPublicKeyCose();

    void setPublicKeyCose(String publicKeyCose);

    long getSignatureCount();

    void setSignatureCount(long count);

    String getLabel();

    void setLabel(String label);

    long getCreated();

    void setCreated(long created);

    long getLastUsed();

    void setLastUsed(long lastUsed);
}
