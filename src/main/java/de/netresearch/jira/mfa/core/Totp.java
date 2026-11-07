package de.netresearch.jira.mfa.core;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalLong;

/**
 * RFC 6238 time-based one-time passwords: 30-second steps, 6 digits,
 * HMAC-SHA1 (the parameters every authenticator app supports).
 * Code generation is delegated to java-otp; this class adds secret creation,
 * the otpauth URI and a verification window with replay protection.
 */
public final class Totp {
    public static final Duration STEP = Duration.ofSeconds(30);
    public static final int DIGITS = 6;
    public static final String ALGORITHM = "HmacSHA1";
    /** Accept codes from one step before and after the current one (clock drift). */
    public static final int WINDOW = 1;
    private static final int SECRET_BYTES = 20;

    private final TimeBasedOneTimePasswordGenerator generator;
    private final SecureRandom random;

    public Totp() {
        this(new SecureRandom());
    }

    public Totp(SecureRandom random) {
        // The two-argument constructor uses HMAC-SHA1, the RFC 6238 default.
        this.generator = new TimeBasedOneTimePasswordGenerator(STEP, DIGITS);
        this.random = random;
    }

    public byte[] newSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        random.nextBytes(secret);
        return secret;
    }

    public static String base32(byte[] secret) {
        return new Base32().encodeToString(secret).replace("=", "");
    }

    public static long step(Instant time) {
        return Math.floorDiv(time.getEpochSecond(), STEP.getSeconds());
    }

    public String code(byte[] secret, Instant time) {
        try {
            int value = generator.generateOneTimePassword(new SecretKeySpec(secret, ALGORITHM), time);
            return String.format("%0" + DIGITS + "d", value);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("TOTP secret rejected by HMAC", e);
        }
    }

    /**
     * Verifies a code. Returns the matched time step, or empty when the code is
     * wrong or belongs to a step at or before {@code lastUsedStep} (replay).
     */
    public OptionalLong verify(byte[] secret, String input, Instant now, long lastUsedStep) {
        String code = normalize(input);
        if (code == null) {
            return OptionalLong.empty();
        }
        long current = step(now);
        for (long s = current - WINDOW; s <= current + WINDOW; s++) {
            if (s <= lastUsedStep) {
                continue;
            }
            String expected = code(secret, Instant.ofEpochSecond(s * STEP.getSeconds()));
            if (MessageDigestCompare.equal(expected, code)) {
                return OptionalLong.of(s);
            }
        }
        return OptionalLong.empty();
    }

    static String normalize(String input) {
        if (input == null) {
            return null;
        }
        String digits = input.replaceAll("\\s", "");
        if (digits.length() != DIGITS || !digits.chars().allMatch(Character::isDigit)) {
            return null;
        }
        return digits;
    }

    /** otpauth:// URI as understood by Google Authenticator, Aegis, 1Password and others. */
    public static String otpauthUri(String issuer, String account, byte[] secret) {
        String label = enc(issuer) + ":" + enc(account);
        return "otpauth://totp/" + label + "?secret=" + base32(secret)
                + "&issuer=" + enc(issuer) + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP.getSeconds();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
