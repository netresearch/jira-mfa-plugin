package de.netresearch.jira.mfa.service;

import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import de.netresearch.jira.mfa.core.MfaSettings;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SettingsStoreTest {
    private static final String NS = "de.netresearch.jira.mfa.";
    private final Map<String, Object> stored = new HashMap<>();

    private SettingsStore store() {
        ClassLoader cl = SettingsStoreTest.class.getClassLoader();
        PluginSettings ps = (PluginSettings) Proxy.newProxyInstance(cl, new Class<?>[]{PluginSettings.class}, (p, m, a) ->
                "put".equals(m.getName()) ? stored.put((String) a[0], a[1]) : stored.get(a[0]));
        return new SettingsStore((PluginSettingsFactory) Proxy.newProxyInstance(cl, new Class<?>[]{PluginSettingsFactory.class}, (p, m, a) -> ps));
    }

    @Test
    void withoutStoredValuesThereIsNoSecondHostName() {
        MfaSettings s = store().get();
        assertEquals(Set.of(), s.relatedOrigins);
        assertEquals("", s.legacyRpId);
        assertEquals(Set.of(), MfaSettings.defaults().relatedOrigins);
        assertEquals("", MfaSettings.defaults().legacyRpId);
    }

    @Test
    void savedValuesAreReadBack() {
        MfaSettings s = new MfaSettings(true, Set.of(), Set.of(), Set.of(), 14, MfaSettings.BasicAuthPolicy.BLOCK, Set.of(), "jira.example.org",
                Set.of("https://jira.example.com", "https://jira.example.org:8443"), "jira.example.com", "Issuer", 5, 15);
        store().save(s);
        MfaSettings read = store().get();
        assertEquals(s.relatedOrigins, read.relatedOrigins);
        assertEquals("jira.example.com", read.legacyRpId);
        assertEquals("jira.example.org", read.rpId);
        assertEquals("Issuer", read.issuer);
    }

    @Test
    void aStoredOriginThatIsNotValidIsLeftOut() {
        stored.put(NS + "relatedOrigins", "https://*.example.org\nhttps://JIRA.example.org:443\nhttp://jira.example.net");
        assertEquals(List.of("https://jira.example.org"), List.copyOf(store().get().relatedOrigins));
    }
}
