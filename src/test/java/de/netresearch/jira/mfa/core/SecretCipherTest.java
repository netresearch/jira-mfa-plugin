package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretCipherTest {
    @Test
    void roundTripWithPersistedKey(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("mfa").resolve("secret.key");
        SecretCipher c1 = SecretCipher.fromKeyFile(key);
        assertTrue(Files.exists(key));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(key)));
        byte[] plain = "totp-secret-bytes".getBytes(StandardCharsets.UTF_8);
        String enc = c1.encrypt(plain);
        assertTrue(enc.startsWith("v1:"));
        assertNotEquals(enc, c1.encrypt(plain), "random IV");
        SecretCipher c2 = SecretCipher.fromKeyFile(key);
        assertArrayEquals(plain, c2.decrypt(enc), "key survives a restart");
    }

    @Test
    void tamperingAndWrongKeyAreDetected(@TempDir Path dir) throws Exception {
        SecretCipher c = SecretCipher.fromKeyFile(dir.resolve("a.key"));
        SecretCipher other = SecretCipher.fromKeyFile(dir.resolve("b.key"));
        String enc = c.encrypt(new byte[]{1, 2, 3});
        // Flip a bit in the decoded bytes. Editing a base64 character instead can hit
        // the padding bits of the last group and leave the bytes unchanged.
        byte[] raw = java.util.Base64.getDecoder().decode(enc.substring("v1:".length()));
        for (int i : new int[]{0, 12, raw.length - 1}) { // IV, ciphertext, tag
            byte[] tampered = raw.clone();
            tampered[i] ^= 0x01;
            String t = "v1:" + java.util.Base64.getEncoder().encodeToString(tampered);
            assertThrows(IllegalStateException.class, () -> c.decrypt(t), "byte " + i);
        }
        assertThrows(IllegalStateException.class, () -> other.decrypt(enc));
        assertThrows(IllegalArgumentException.class, () -> c.decrypt("plain"));
    }
}
