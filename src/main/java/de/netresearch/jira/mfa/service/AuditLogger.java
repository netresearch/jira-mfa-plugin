package de.netresearch.jira.mfa.service;

import com.atlassian.audit.api.AuditService;
import com.atlassian.audit.entity.AuditAttribute;
import com.atlassian.audit.entity.AuditEvent;
import com.atlassian.audit.entity.AuditResource;
import com.atlassian.audit.entity.AuditType;
import com.atlassian.audit.entity.CoverageArea;
import com.atlassian.audit.entity.CoverageLevel;
import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Map;

/**
 * Writes MFA events to Jira's audit log (Administration &gt; System &gt; Audit log,
 * category "Security") and to the application log. The audit write never
 * breaks the request: a failure is logged and swallowed.
 */
@Named
public class AuditLogger {
    private static final Logger LOG = LoggerFactory.getLogger("de.netresearch.jira.mfa.audit");
    private static final String CATEGORY_KEY = "de.netresearch.jira.mfa.audit.category";

    public enum Action {
        TOTP_ENROLLED("TOTP enrolled"),
        TOTP_REMOVED("TOTP removed"),
        PASSKEY_REGISTERED("Passkey registered"),
        PASSKEY_REMOVED("Passkey removed"),
        RECOVERY_CODES_GENERATED("Recovery codes generated"),
        RECOVERY_CODE_USED("Recovery code used"),
        SECOND_STEP_SUCCEEDED("Second factor verified"),
        SECOND_STEP_FAILED("Second factor failed"),
        LOCKED_OUT("Second factor locked after repeated failures"),
        BASIC_AUTH_REJECTED("Basic authentication rejected"),
        ADMIN_RESET("Second factors reset by administrator"),
        SETTINGS_CHANGED("MFA settings changed");

        final String label;

        Action(String label) {
            this.label = label;
        }
    }

    private final AuditService auditService;

    @Inject
    public AuditLogger(@ComponentImport AuditService auditService) {
        this.auditService = auditService;
    }

    public void log(Action action, ApplicationUser subject, Map<String, String> details) {
        String who = subject == null ? "-" : subject.getUsername();
        LOG.info("{} user={} {}", action.label, who, details);
        try {
            AuditType type = AuditType.fromI18nKeys(CoverageArea.SECURITY, CoverageLevel.BASE,
                            CATEGORY_KEY, "de.netresearch.jira.mfa.audit." + action.name().toLowerCase())
                    .withCategoryTranslation("Multi-factor authentication")
                    .withActionTranslation(action.label)
                    .build();
            AuditEvent.Builder b = AuditEvent.builder(type);
            if (subject != null) {
                b.affectedObject(AuditResource.builder(subject.getUsername(), "USER").id(subject.getKey()).build());
            }
            for (Map.Entry<String, String> e : details.entrySet()) {
                b.extraAttribute(AuditAttribute.fromI18nKeys(e.getKey(), e.getValue() == null ? "" : e.getValue())
                        .withNameTranslation(e.getKey()).build());
            }
            auditService.audit(b.build());
        } catch (RuntimeException e) {
            LOG.warn("could not write audit event {}", action, e);
        }
    }
}
