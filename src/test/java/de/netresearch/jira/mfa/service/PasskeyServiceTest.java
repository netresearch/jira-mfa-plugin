package de.netresearch.jira.mfa.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.exception.RegistrationFailedException;
import de.netresearch.jira.mfa.ao.MfaPasskey;
import de.netresearch.jira.mfa.ao.MfaUser;
import de.netresearch.jira.mfa.core.MfaSettings;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Whole ceremonies against the WebAuthn library, with a software authenticator and an in-memory store. */
class PasskeyServiceTest {
    private static final String OLD = "jira.example.com";
    private static final String NEW = "jira.example.org";
    private static final String OLD_ORIGIN = "https://jira.example.com";
    private static final String NEW_ORIGIN = "https://jira.example.org";
    private static final String USER = "JIRAUSER1";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final FakeStore store = new FakeStore();
    private MfaSettings current = settings("", Set.of(), "");
    private String baseUrl = OLD_ORIGIN;
    private final PasskeyService service = new PasskeyService(store, new SettingsStore(null) {
        @Override
        public MfaSettings get() {
            return current;
        }
    }, new JiraEnvironment() {
        @Override
        public String baseUrl() {
            return baseUrl;
        }
    });

    private static MfaSettings settings(String rpId, Set<String> related, String legacyRpId) {
        return new MfaSettings(true, Set.of(), Set.of(), Set.of(), 14, MfaSettings.BasicAuthPolicy.BLOCK, Set.of(), rpId, related, legacyRpId,
                "Jira", 5, 15);
    }

    @Test
    void withDefaultSettingsOnlyTheBaseUrlIsAllowed() throws Exception {
        assertEquals(Set.of(OLD_ORIGIN), service.allowedOrigins());
        Key key = register(OLD_ORIGIN);
        assertEquals(OLD, store.rows.get(0).get("getRpId"));
        assertTrue(login(key, OLD, OLD_ORIGIN));
        assertFalse(login(key, OLD, NEW_ORIGIN), "another origin");
        assertThrows(RegistrationFailedException.class, () -> register(NEW_ORIGIN));
    }

    @Test
    void aRelatedOriginMayUseThePasskeysOfTheOldHost() throws Exception {
        Key key = register(OLD_ORIGIN);
        current = settings("", Set.of(NEW_ORIGIN), "");
        assertTrue(login(key, NEW, NEW_ORIGIN));
        assertFalse(login(key, NEW, "https://jira.example.net"), "not configured, whatever host the request names");
        register(NEW_ORIGIN);
        assertEquals(OLD, store.rows.get(1).get("getRpId"), "registration keeps the configured ID, also from the new host");
    }

    @Test
    void oldPasskeysWithoutStoredIdKeepWorkingAfterTheMove() throws Exception {
        Key key = register(OLD_ORIGIN);
        store.rows.get(0).put("getRpId", null);
        current = settings("", Set.of(OLD_ORIGIN, NEW_ORIGIN), OLD);
        baseUrl = NEW_ORIGIN;
        assertTrue(login(key, NEW, NEW_ORIGIN));
        current = settings("", Set.of(OLD_ORIGIN, NEW_ORIGIN), "");
        assertFalse(login(key, NEW, NEW_ORIGIN), "without legacyRpId the row counts as the new host's");
    }

    @Test
    void onlyTheChosenGroupIsOffered() throws Exception {
        Key oldKey = register(OLD_ORIGIN);
        current = settings(NEW, Set.of(OLD_ORIGIN, NEW_ORIGIN), OLD);
        Key newKey = register(NEW_ORIGIN);
        assertEquals(NEW, store.rows.get(1).get("getRpId"));
        assertOffered(OLD, Set.of(oldKey.idText()), service.startAssertion(USER, OLD));
        assertOffered(NEW, Set.of(newKey.idText()), service.startAssertion(USER, NEW));
        assertOffered(NEW, Set.of(newKey.idText()), service.startAssertion(USER, null));
        assertOffered(OLD, Set.of(oldKey.idText()), service.startAssertion(USER, "x.jira.example.com"));
    }

    @Test
    void aPasskeyOfAnotherGroupIsRefusedAtTheEnd() throws Exception {
        Key key = register(OLD_ORIGIN);
        String request = service.startAssertion(USER, OLD);
        assertTrue(service.finishAssertion(USER, request, key.assertion(request, OLD_ORIGIN)));
        String second = service.startAssertion(USER, OLD);
        // offered under the old ID, but by now stored under the new one; the signature itself is right
        store.rows.get(0).put("getRpId", NEW);
        assertFalse(service.finishAssertion(USER, second, key.assertion(second, OLD_ORIGIN)));
    }

    @Test
    void aSettingsChangeDuringACeremonyDoesNotMixTheIds() throws Exception {
        Key key = new Key();
        String registration = service.startRegistration(USER, "alice", "Alice");
        current = settings(NEW, Set.of(OLD_ORIGIN, NEW_ORIGIN), OLD);
        String response = key.attestation(registration, OLD_ORIGIN);
        assertDoesNotThrow(() -> service.finishRegistration(USER, registration, response, "key"), "checked against the ID of the request");
        assertEquals(OLD, store.rows.get(0).get("getRpId"), "the ID of the request, not the new setting");
        current = settings("", Set.of(), "");
        String assertion = service.startAssertion(USER, OLD);
        current = settings(NEW, Set.of(OLD_ORIGIN, NEW_ORIGIN), OLD);
        assertTrue(service.finishAssertion(USER, assertion, key.assertion(assertion, OLD_ORIGIN)));
    }

    @Test
    void onlyPasskeysOfTheSameIdAreExcludedFromANewRegistration() throws Exception {
        Key oldKey = register(OLD_ORIGIN);
        assertEquals(Set.of(oldKey.idText()), ids(JSON.readTree(service.startRegistration(USER, "alice", "Alice")).get("excludeCredentials")));
        current = settings(NEW, Set.of(OLD_ORIGIN, NEW_ORIGIN), OLD);
        assertEquals(Set.of(), ids(JSON.readTree(service.startRegistration(USER, "alice", "Alice")).get("excludeCredentials")),
                "the authenticator of the old passkey may register again");
    }

    @Test
    void aCredentialIdStaysUniqueAcrossTheIds() throws Exception {
        Key key = register(OLD_ORIGIN);
        current = settings(NEW, Set.of(OLD_ORIGIN, NEW_ORIGIN), OLD);
        String registration = service.startRegistration(USER, "alice", "Alice");
        assertThrows(RegistrationFailedException.class, () ->
                service.finishRegistration(USER, registration, key.attestation(registration, NEW_ORIGIN), "key"));
    }

    @Test
    void aUserWithoutPasskeysGetsTheConfiguredId() throws Exception {
        store.userHandle = "AAAA";
        JsonNode pk = options(service.startAssertion(USER, NEW));
        assertEquals(OLD, pk.get("rpId").asText());
        assertEquals(Set.of(), ids(pk.get("allowCredentials")));
        assertNull(store.used);
    }

    private static void assertOffered(String rpId, Set<String> ids, String request) throws Exception {
        assertEquals(rpId, options(request).get("rpId").asText());
        assertEquals(ids, ids(options(request).get("allowCredentials")));
    }

    private static JsonNode options(String request) throws Exception {
        return JSON.readTree(request).get("publicKeyCredentialRequestOptions");
    }

    private static Set<String> ids(JsonNode list) {
        Set<String> out = new TreeSet<>();
        if (list != null) {
            list.forEach(n -> out.add(n.get("id").asText()));
        }
        return out;
    }

    private Key register(String origin) throws Exception {
        Key key = new Key();
        String request = service.startRegistration(USER, "alice", "Alice");
        service.finishRegistration(USER, request, key.attestation(request, origin), "key");
        return key;
    }

    private boolean login(Key key, String requestHost, String origin) throws Exception {
        String request = service.startAssertion(USER, requestHost);
        return service.finishAssertion(USER, request, key.assertion(request, origin));
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** A software authenticator with one ES256 credential, bound to the RP ID it was registered for. */
    private static final class Key {
        private static int count;
        private final byte[] id = ("credential-" + ++count).getBytes(StandardCharsets.UTF_8);
        private final KeyPair pair;
        private String rpId;

        Key() throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            pair = g.generateKeyPair();
        }

        String idText() {
            return b64(id);
        }

        String attestation(String request, String origin) throws Exception {
            JsonNode r = JSON.readTree(request);
            rpId = r.get("rp").get("id").asText();
            ECPublicKey pub = (ECPublicKey) pair.getPublic();
            byte[] cose = CBORObject.NewMap().Add(1, 2).Add(3, -7).Add(-1, 1)
                    .Add(-2, unsigned(pub.getW().getAffineX())).Add(-3, unsigned(pub.getW().getAffineY())).EncodeToBytes();
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            data.write(authenticatorData(rpId, 0x45));
            data.write(new byte[16]);
            data.write(ByteBuffer.allocate(2).putShort((short) id.length).array());
            data.write(id);
            data.write(cose);
            byte[] object = CBORObject.NewMap().Add("fmt", "none").Add("attStmt", CBORObject.NewMap()).Add("authData", data.toByteArray()).EncodeToBytes();
            return response(Map.of("attestationObject", b64(object),
                    "clientDataJSON", b64(clientData("webauthn.create", r.get("challenge").asText(), origin))));
        }

        String assertion(String request, String origin) throws Exception {
            JsonNode r = options(request);
            byte[] data = authenticatorData(rpId, 0x05);
            byte[] client = clientData("webauthn.get", r.get("challenge").asText(), origin);
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(pair.getPrivate());
            s.update(data);
            s.update(MessageDigest.getInstance("SHA-256").digest(client));
            return response(Map.of("authenticatorData", b64(data), "clientDataJSON", b64(client), "signature", b64(s.sign())));
        }

        private String response(Map<String, String> response) throws Exception {
            return JSON.writeValueAsString(Map.of("id", idText(), "rawId", idText(), "type", "public-key",
                    "response", response, "clientExtensionResults", Map.of()));
        }

        private static byte[] clientData(String type, String challenge, String origin) throws Exception {
            return JSON.writeValueAsBytes(Map.of("type", type, "challenge", challenge, "origin", origin));
        }

        private static byte[] authenticatorData(String rpId, int flags) throws Exception {
            return ByteBuffer.allocate(37).put(MessageDigest.getInstance("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8)))
                    .put((byte) flags).putInt(0).array();
        }

        private static byte[] unsigned(BigInteger i) {
            byte[] raw = i.toByteArray();
            byte[] out = new byte[32];
            int n = Math.min(raw.length, 32);
            System.arraycopy(raw, raw.length - n, out, 32 - n, n);
            return out;
        }
    }

    /** Entities are proxies over a map from getter name to value. */
    private static final class FakeStore extends MfaStore {
        final List<Map<String, Object>> rows = new ArrayList<>();
        String userHandle;
        String used;

        FakeStore() {
            super(null);
        }

        private static <T> T entity(Class<T> type, Map<String, Object> values) {
            return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, a) -> values.get(m.getName())));
        }

        private List<MfaPasskey> find(String getter, String value) {
            return rows.stream().filter(r -> value.equals(r.get(getter))).map(r -> entity(MfaPasskey.class, r)).collect(Collectors.toList());
        }

        @Override
        public List<MfaPasskey> passkeys(String userKey) {
            return find("getUserKey", userKey);
        }

        @Override
        public List<MfaPasskey> passkeysByCredentialId(String credentialId) {
            return find("getCredentialId", credentialId);
        }

        @Override
        public void addPasskey(String userKey, String credentialId, String rpId, String publicKeyCose, long signatureCount, String label, long now) {
            Map<String, Object> r = new HashMap<>();
            r.put("getUserKey", userKey);
            r.put("getCredentialId", credentialId);
            r.put("getRpId", rpId);
            r.put("getPublicKeyCose", publicKeyCose);
            r.put("getSignatureCount", signatureCount);
            rows.add(r);
        }

        @Override
        public void updatePasskeyUse(String credentialId, long signatureCount, long now) {
            used = credentialId;
        }

        @Override
        public MfaUser getOrCreateUser(String userKey) {
            Map<String, Object> u = new HashMap<>();
            u.put("getUserKey", USER);
            u.put("getUserHandle", userHandle);
            return entity(MfaUser.class, u);
        }

        @Override
        public Optional<MfaUser> findUser(String userKey) {
            return USER.equals(userKey) ? Optional.of(getOrCreateUser(userKey)) : Optional.empty();
        }

        @Override
        public Optional<MfaUser> findUserByHandle(String handle) {
            return handle.equals(userHandle) ? findUser(USER) : Optional.empty();
        }

        @Override
        public void setUserHandle(String userKey, String handle) {
            userHandle = handle;
        }
    }
}
