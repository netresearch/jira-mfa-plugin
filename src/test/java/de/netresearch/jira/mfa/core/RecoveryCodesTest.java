package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecoveryCodesTest {
    private final RecoveryCodes codes = new RecoveryCodes();

    @Test
    void generatesTenDistinctWellFormedCodes() {
        List<String> list = codes.generate();
        assertEquals(RecoveryCodes.COUNT, list.size());
        assertEquals(list.size(), new HashSet<>(list).size());
        for (String c : list) {
            assertTrue(c.matches("[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}"), c);
        }
    }

    @Test
    void hashIsSaltedAndVerifiable() {
        String code = codes.generate().get(0);
        String h1 = codes.hash(code);
        String h2 = codes.hash(code);
        assertNotEquals(h1, h2, "salt makes hashes differ");
        assertFalse(h1.contains(code.replace("-", "")), "plain code not stored");
        assertTrue(RecoveryCodes.matches(code, h1));
        assertTrue(RecoveryCodes.matches(code, h2));
    }

    @Test
    void inputIsNormalized() {
        String code = codes.generate().get(0);
        String h = codes.hash(code);
        assertTrue(RecoveryCodes.matches(code.toLowerCase(), h));
        assertTrue(RecoveryCodes.matches(code.replace("-", ""), h));
        assertTrue(RecoveryCodes.matches(" " + code.replace("-", " - ") + " ", h));
    }

    @Test
    void wrongOrMalformedInputDoesNotMatch() {
        List<String> list = codes.generate();
        String h = codes.hash(list.get(0));
        assertFalse(RecoveryCodes.matches(list.get(1), h));
        assertFalse(RecoveryCodes.matches("123456", h), "a TOTP code is never a recovery code");
        assertFalse(RecoveryCodes.matches(null, h));
        assertFalse(RecoveryCodes.matches(list.get(0), null));
        assertFalse(RecoveryCodes.matches(list.get(0), "sha1$x"));
        assertNull(RecoveryCodes.normalize("ABCDE-FGHI1"), "1 is not in the alphabet");
        assertThrows(IllegalArgumentException.class, () -> codes.hash("nope"));
    }
}
