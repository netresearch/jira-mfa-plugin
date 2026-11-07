package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LogTextTest {
    @Test
    void lineBreaksAndOtherControlCharactersAreReplaced() {
        assertEquals("/x_INFO forged entry", LogText.clean("/x\nINFO forged entry"));
        assertEquals("a_b_c_d_e", LogText.clean("a\rb\tc\u007fd e"));
        assertEquals("/secure/Dashboard.jspa", LogText.clean("/secure/Dashboard.jspa"));
        assertEquals("null", LogText.clean(null));
        assertEquals("{label=a_b}", LogText.clean(Map.of("label", "a\nb")), "maps are cleaned as a whole");
    }
}
