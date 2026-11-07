package de.netresearch.jira.mfa.service;

import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import de.netresearch.jira.mfa.core.MfaSettings;

import javax.inject.Inject;
import javax.inject.Named;

/** Reads and writes {@link MfaSettings} in Jira's global plugin settings. */
@Named
public class SettingsStore {
    private static final String NS = "de.netresearch.jira.mfa.";

    private final PluginSettingsFactory factory;
    private volatile MfaSettings cached;
    private volatile long loadedAt;
    /** Other Data Center nodes see a saved change within this time. */
    static final long TTL_MILLIS = 30_000L;

    @Inject
    public SettingsStore(@ComponentImport PluginSettingsFactory factory) {
        this.factory = factory;
    }

    public MfaSettings get() {
        MfaSettings c = cached;
        long now = System.currentTimeMillis();
        if (c == null || now - loadedAt >= TTL_MILLIS) {
            c = load();
            cached = c;
            loadedAt = now;
        }
        return c;
    }

    private MfaSettings load() {
        PluginSettings ps = factory.createGlobalSettings();
        MfaSettings d = MfaSettings.defaults();
        return new MfaSettings(
                bool(ps, "enabled", d.enabled),
                MfaSettings.parseList(str(ps, "enforcedGroups", "")),
                MfaSettings.parseList(str(ps, "exemptGroups", "")),
                MfaSettings.parseList(str(ps, "exemptUsers", "")),
                integer(ps, "graceDays", d.graceDays),
                MfaSettings.BasicAuthPolicy.valueOf(str(ps, "basicAuthPolicy", d.basicAuthPolicy.name())),
                MfaSettings.parseList(str(ps, "basicAuthAllowedUsers", "")),
                str(ps, "rpId", d.rpId),
                str(ps, "issuer", d.issuer),
                integer(ps, "maxFailures", d.maxFailures),
                integer(ps, "lockoutMinutes", d.lockoutMinutes));
    }

    public synchronized void save(MfaSettings s) {
        PluginSettings ps = factory.createGlobalSettings();
        ps.put(NS + "enabled", Boolean.toString(s.enabled));
        ps.put(NS + "enforcedGroups", MfaSettings.formatList(s.enforcedGroups));
        ps.put(NS + "exemptGroups", MfaSettings.formatList(s.exemptGroups));
        ps.put(NS + "exemptUsers", MfaSettings.formatList(s.exemptUsers));
        ps.put(NS + "graceDays", Integer.toString(s.graceDays));
        ps.put(NS + "basicAuthPolicy", s.basicAuthPolicy.name());
        ps.put(NS + "basicAuthAllowedUsers", MfaSettings.formatList(s.basicAuthAllowedUsers));
        ps.put(NS + "rpId", s.rpId);
        ps.put(NS + "issuer", s.issuer);
        ps.put(NS + "maxFailures", Integer.toString(s.maxFailures));
        ps.put(NS + "lockoutMinutes", Integer.toString(s.lockoutMinutes));
        cached = s;
        loadedAt = System.currentTimeMillis();
    }

    private static String str(PluginSettings ps, String key, String def) {
        Object v = ps.get(NS + key);
        return v instanceof String ? (String) v : def;
    }

    private static boolean bool(PluginSettings ps, String key, boolean def) {
        Object v = ps.get(NS + key);
        return v instanceof String ? Boolean.parseBoolean((String) v) : def;
    }

    private static int integer(PluginSettings ps, String key, int def) {
        Object v = ps.get(NS + key);
        try {
            return v instanceof String ? Integer.parseInt((String) v) : def;
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
