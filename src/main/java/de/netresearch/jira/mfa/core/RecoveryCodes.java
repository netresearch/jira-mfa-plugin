package de.netresearch.jira.mfa.core;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * One-time recovery codes. A code is 10 characters from a 32-letter alphabet
 * without look-alikes (50 bits), shown as {@code XXXXX-XXXXX}. Only a salted
 * PBKDF2-HMAC-SHA256 hash is stored, as {@code pbkdf2$<iterations>$<salt>$<hash>}.
 */
public final class RecoveryCodes {
    public static final int COUNT = 10;
    static final int LENGTH = 10;
    static final int ITERATIONS = 60_000;
    private static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private final SecureRandom random;

    public RecoveryCodes() {
        this(new SecureRandom());
    }

    public RecoveryCodes(SecureRandom random) {
        this.random = random;
    }

    public List<String> generate() {
        List<String> codes = new ArrayList<>(COUNT);
        for (int i = 0; i < COUNT; i++) {
            StringBuilder sb = new StringBuilder(LENGTH + 1);
            for (int j = 0; j < LENGTH; j++) {
                if (j == LENGTH / 2) {
                    sb.append('-');
                }
                sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
            }
            codes.add(sb.toString());
        }
        return codes;
    }

    /** Uppercases and strips separators; returns null for input that cannot be a code. */
    public static String normalize(String input) {
        if (input == null) {
            return null;
        }
        String s = input.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
        if (s.length() != LENGTH) {
            return null;
        }
        for (char c : s.toCharArray()) {
            if (new String(ALPHABET).indexOf(c) < 0) {
                return null;
            }
        }
        return s;
    }

    public String hash(String code) {
        String normalized = normalize(code);
        if (normalized == null) {
            throw new IllegalArgumentException("not a recovery code");
        }
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = pbkdf2(normalized, salt, ITERATIONS);
        Base64.Encoder b64 = Base64.getEncoder();
        return "pbkdf2$" + ITERATIONS + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(hash);
    }

    public static boolean matches(String input, String stored) {
        String normalized = normalize(input);
        if (normalized == null || stored == null) {
            return false;
        }
        String[] parts = stored.split("\\$");
        if (parts.length != 4 || !"pbkdf2".equals(parts[0])) {
            return false;
        }
        int iterations = Integer.parseInt(parts[1]);
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] expected = Base64.getDecoder().decode(parts[3]);
        return MessageDigest.isEqual(expected, pbkdf2(normalized, salt, iterations));
    }

    private static byte[] pbkdf2(String code, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(code.toCharArray(), salt, iterations, HASH_BITS);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 unavailable", e);
        }
    }
}
