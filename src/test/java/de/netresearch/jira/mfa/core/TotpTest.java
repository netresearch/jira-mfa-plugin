package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TotpTest {
    /** RFC 6238 appendix B, SHA1 seed. */
    private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private final Totp totp = new Totp();

    @Test
    void matchesRfc6238Vectors() {
        // The RFC lists 8-digit values; a 6-digit code is the same value mod 10^6.
        assertEquals("287082", totp.code(RFC_SECRET, Instant.ofEpochSecond(59)));
        assertEquals("081804", totp.code(RFC_SECRET, Instant.ofEpochSecond(1111111109)));
        assertEquals("050471", totp.code(RFC_SECRET, Instant.ofEpochSecond(1111111111)));
        assertEquals("005924", totp.code(RFC_SECRET, Instant.ofEpochSecond(1234567890)));
        assertEquals("279037", totp.code(RFC_SECRET, Instant.ofEpochSecond(2000000000)));
    }

    @Test
    void acceptsCurrentAndAdjacentStepsOnly() {
        Instant now = Instant.ofEpochSecond(1234567890);
        long step = Totp.step(now);
        String prev = totp.code(RFC_SECRET, now.minusSeconds(30));
        String next = totp.code(RFC_SECRET, now.plusSeconds(30));
        String twoAgo = totp.code(RFC_SECRET, now.minusSeconds(60));
        assertEquals(OptionalLong.of(step), totp.verify(RFC_SECRET, "005924", now, Long.MIN_VALUE));
        assertEquals(OptionalLong.of(step - 1), totp.verify(RFC_SECRET, prev, now, Long.MIN_VALUE));
        assertEquals(OptionalLong.of(step + 1), totp.verify(RFC_SECRET, next, now, Long.MIN_VALUE));
        assertFalse(totp.verify(RFC_SECRET, twoAgo, now, Long.MIN_VALUE).isPresent());
    }

    @Test
    void rejectsReplayOfUsedStep() {
        Instant now = Instant.ofEpochSecond(1234567890);
        long step = Totp.step(now);
        assertFalse(totp.verify(RFC_SECRET, "005924", now, step).isPresent(), "same step again");
        assertFalse(totp.verify(RFC_SECRET, "005924", now, step + 1).isPresent(), "older than last used");
        assertTrue(totp.verify(RFC_SECRET, "005924", now, step - 1).isPresent());
    }

    @Test
    void rejectsMalformedInput() {
        Instant now = Instant.ofEpochSecond(1234567890);
        assertFalse(totp.verify(RFC_SECRET, null, now, Long.MIN_VALUE).isPresent());
        assertFalse(totp.verify(RFC_SECRET, "", now, Long.MIN_VALUE).isPresent());
        assertFalse(totp.verify(RFC_SECRET, "05924", now, Long.MIN_VALUE).isPresent());
        assertFalse(totp.verify(RFC_SECRET, "0059245", now, Long.MIN_VALUE).isPresent());
        assertFalse(totp.verify(RFC_SECRET, "00592a", now, Long.MIN_VALUE).isPresent());
        assertTrue(totp.verify(RFC_SECRET, " 005 924 ", now, Long.MIN_VALUE).isPresent(), "spaces are ignored");
    }

    @Test
    void secretsAreRandomAnd160Bit() {
        byte[] a = totp.newSecret();
        byte[] b = totp.newSecret();
        assertEquals(20, a.length);
        assertFalse(java.util.Arrays.equals(a, b));
        assertEquals(32, Totp.base32(a).length());
    }

    @Test
    void otpauthUriCarriesParameters() {
        String uri = Totp.otpauthUri("Netresearch Jira", "j.doe", RFC_SECRET);
        assertEquals("otpauth://totp/Netresearch%20Jira:j.doe?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                + "&issuer=Netresearch%20Jira&algorithm=SHA1&digits=6&period=30", uri);
    }
}
