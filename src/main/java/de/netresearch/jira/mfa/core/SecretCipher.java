package de.netresearch.jira.mfa.core;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM encryption of stored TOTP secrets. The key lives in a file
 * outside the database (by default {@code $JIRA_HOME/data/mfa/secret.key}),
 * so a database dump alone does not reveal the secrets. Losing the key file
 * makes every stored TOTP secret unreadable; it is part of the backup.
 * Ciphertext format: {@code v1:<base64(iv || ciphertext+tag)>}.
 */
public final class SecretCipher {
    private static final String PREFIX = "v1:";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public SecretCipher(SecretKey key) {
        this.key = key;
    }

    /** Loads the key file, creating it (mode 600) when it does not exist yet. */
    public static SecretCipher fromKeyFile(Path file) throws IOException {
        if (!Files.exists(file)) {
            Files.createDirectories(file.getParent());
            try {
                KeyGenerator gen = KeyGenerator.getInstance("AES");
                gen.init(256);
                byte[] raw = gen.generateKey().getEncoded();
                Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
                Files.write(tmp, Base64.getEncoder().encode(raw), StandardOpenOption.CREATE_NEW);
                try {
                    Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
                } catch (UnsupportedOperationException ignored) {
                    // non-POSIX file system
                }
                Files.move(tmp, file);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("AES unavailable", e);
            }
        }
        byte[] raw = Base64.getDecoder().decode(new String(Files.readAllBytes(file), StandardCharsets.US_ASCII).trim());
        if (raw.length != 32) {
            throw new IllegalStateException("MFA key file " + file + " does not hold a 256-bit key");
        }
        return new SecretCipher(new SecretKeySpec(raw, "AES"));
    }

    public String encrypt(byte[] plain) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = c.doFinal(plain);
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return PREFIX + Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    public byte[] decrypt(String stored) {
        if (stored == null || !stored.startsWith(PREFIX)) {
            throw new IllegalArgumentException("unknown ciphertext format");
        }
        byte[] in = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
        if (in.length <= IV_BYTES) {
            throw new IllegalArgumentException("ciphertext too short");
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, in, 0, IV_BYTES));
            return c.doFinal(in, IV_BYTES, in.length - IV_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("decryption failed (wrong key file?)", e);
        }
    }
}
