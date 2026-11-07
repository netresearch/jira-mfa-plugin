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
        char[] chars = enc.toCharArray();
        chars[chars.length - 3] = chars[chars.length - 3] == 'A' ? 'B' : 'A';
        assertThrows(IllegalStateException.class, () -> c.decrypt(new String(chars)));
        assertThrows(IllegalStateException.class, () -> other.decrypt(enc));
        assertThrows(IllegalArgumentException.class, () -> c.decrypt("plain"));
    }
}
