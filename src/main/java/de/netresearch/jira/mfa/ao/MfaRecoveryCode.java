package de.netresearch.jira.mfa.ao;

import net.java.ao.Entity;
import net.java.ao.Preload;
import net.java.ao.schema.Indexed;
import net.java.ao.schema.NotNull;
import net.java.ao.schema.Table;

/** A hashed one-time recovery code. Used codes are deleted. */
@Preload
@Table("RECOVERY_CODE")
public interface MfaRecoveryCode extends Entity {
    @NotNull
    @Indexed
    String getUserKey();

    void setUserKey(String userKey);

    @NotNull
    String getCodeHash();

    void setCodeHash(String codeHash);
}
