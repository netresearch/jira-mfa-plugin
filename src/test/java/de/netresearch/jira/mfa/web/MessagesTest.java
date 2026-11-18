package de.netresearch.jira.mfa.web;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessagesTest {
    private static Properties load(String name) throws IOException {
        Properties p = new Properties();
        try (InputStream in = MessagesTest.class.getResourceAsStream("/i18n/" + name)) {
            p.load(in);
        }
        return p;
    }

    @Test
    void englishAndGermanHaveTheSameKeys() throws IOException {
        Set<String> en = new TreeSet<>(load("mfa.properties").stringPropertyNames());
        Set<String> de = new TreeSet<>(load("mfa_de.properties").stringPropertyNames());
        assertEquals(en, de);
        assertTrue(en.stream().anyMatch(k -> k.startsWith(Messages.PREFIX)), "page texts present");
    }

    @Test
    void textsCarryNoMarkupNoApostropheAndParse() throws IOException {
        for (String file : new String[] {"mfa.properties", "mfa_de.properties"}) {
            Properties p = load(file);
            for (String k : p.stringPropertyNames()) {
                String v = p.getProperty(k);
                assertFalse(v.isBlank(), file + " " + k + " is empty");
                // MessageFormat drops a single apostrophe; the HTML escaping relies on plain text
                assertFalse(v.matches(".*['<>&\"].*"), file + " " + k + " has an apostrophe or HTML character: " + v);
                new MessageFormat(v); // throws on a broken placeholder
            }
        }
    }

    @Test
    void germanUsesUmlautsFromEscapes() throws IOException {
        assertEquals("Anmeldung best\u00e4tigen", load("mfa_de.properties").getProperty(Messages.PREFIX + "verify.heading"));
    }

    private static Messages messages(Map<String, String> m, Locale locale) {
        return new Messages(k -> m.get(k), locale);
    }

    @Test
    void htmlEscapesArgumentsAndKeepsRenderedOnes() {
        Messages m = messages(Map.of(Messages.PREFIX + "a", "Signed in as {0} ({1})."), Locale.ENGLISH);
        assertEquals("Signed in as &lt;b&gt; (x&amp;y).", m.html("a", "<b>", "x&y"));
        assertEquals("Signed in as <strong>A</strong> (b).", m.htmlWith("a", "<strong>A</strong>", "b"));
        assertEquals("Signed in as <b> (x).", m.text("a", "<b>", "x"));
    }

    @Test
    void missingKeyShowsTheKeyAndLangFallsBackToEnglish() {
        Messages m = messages(Map.of(), null);
        assertEquals(Messages.PREFIX + "nope", m.text("nope"));
        assertEquals("en", m.lang());
        assertEquals("de", messages(Map.of(), Locale.GERMANY).lang());
    }

    @Test
    void placeholderForTheScriptSurvivesFormatting() {
        Messages m = messages(Map.of(Messages.PREFIX + "f", "Not accepted ({0}). Try again."), Locale.GERMAN);
        assertEquals("Not accepted ({0}). Try again.", m.text("f", "{0}"));
    }
}
