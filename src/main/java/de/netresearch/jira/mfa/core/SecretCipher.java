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
import java.nio.file.FileAlreadyExistsException;
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

    /**
     * Loads the key file. When it does not exist and {@code mayCreate} is true,
     * a new key is created (mode 600). Callers pass false while encrypted
     * secrets exist: a new key could not read them, and creating one silently
     * would turn a lost key file into a lockout of every TOTP user.
     */
    public static SecretCipher fromKeyFile(Path file, boolean mayCreate) throws IOException {
        if (!Files.exists(file)) {
            if (!mayCreate) {
                throw new IOException("MFA key file " + file + " is missing while encrypted TOTP secrets exist; "
                        + "restore it from the backup of $JIRA_HOME");
            }
            Files.createDirectories(file.getParent());
            publishNewKey(file);
        }
        byte[] raw = Base64.getDecoder().decode(new String(Files.readAllBytes(file), StandardCharsets.US_ASCII).trim());
        if (raw.length != 32) {
            throw new IllegalStateException("MFA key file " + file + " does not hold a 256-bit key");
        }
        return new SecretCipher(new SecretKeySpec(raw, "AES"));
    }

    /**
     * Writes a new key to a temporary file of its own and publishes it under
     * {@code file} without ever replacing an existing key. Several creators
     * (Data Center nodes sharing the home, or a restart racing a running
     * node) can get here at once; exactly one key wins and every creator then
     * reads that one, so no node keeps encrypting with a key that is not on
     * disk. Publication is a hard link, which fails if the target exists; on a
     * file system without hard links a non-replacing move is used instead.
     */
    private static void publishNewKey(Path file) throws IOException {
        byte[] raw;
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(256);
            raw = gen.generateKey().getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES unavailable", e);
        }
        Path tmp = Files.createTempFile(file.getParent(), file.getFileName() + ".", ".tmp");
        try {
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // non-POSIX file system
            }
            Files.write(tmp, Base64.getEncoder().encode(raw), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.createLink(file, tmp);
            } catch (FileAlreadyExistsException anotherCreatorWon) {
                // read the key that is on disk
            } catch (UnsupportedOperationException | IOException noHardLinks) {
                if (Files.exists(file)) {
                    return;
                }
                try {
                    Files.move(tmp, file); // without REPLACE_EXISTING: fails if the target appeared meanwhile
                } catch (FileAlreadyExistsException anotherCreatorWon) {
                    // read the key that is on disk
                }
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
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
