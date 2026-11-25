package de.netresearch.jira.mfa.service;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import de.netresearch.jira.mfa.ao.MfaPasskey;
import de.netresearch.jira.mfa.ao.MfaUser;
import de.netresearch.jira.mfa.core.RelyingParties;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.net.URI;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * WebAuthn ceremonies, delegated to Yubico java-webauthn-server. The plugin
 * stores credentials; all parsing and signature verification is the library's.
 * In WebAuthn terms the "username" is the Jira user key.
 */
@Named
public class PasskeyService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(PasskeyService.class);
    private final MfaStore store;
    private final SettingsStore settings;
    private final JiraEnvironment env;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public PasskeyService(MfaStore store, SettingsStore settings, JiraEnvironment env) {
        this.store = store;
        this.settings = settings;
        this.env = env;
    }

    /** The relying party ID: configured value, or the host of the Jira base URL. */
    public String rpId() {
        String configured = settings.get().rpId;
        if (!configured.isEmpty()) {
            return configured;
        }
        return URI.create(env.baseUrl()).getHost();
    }

    /** The origins a ceremony may come from: the base URL's and the related ones. */
    public Set<String> allowedOrigins() {
        return RelyingParties.allowedOrigins(env.baseUrl(), settings.get().relatedOrigins);
    }

    private String effectiveRpId(MfaPasskey p) {
        return RelyingParties.effectiveRpId(p.getRpId(), settings.get().legacyRpId, rpId());
    }

    /** A relying party for one ceremony; it sees only passkeys of {@code rpId}. */
    private RelyingParty relyingParty(String rpId) {
        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder().id(rpId).name(settings.get().issuer).build())
                .credentialRepository(new Repository(rpId))
                .origins(allowedOrigins())
                .preferredPubkeyParams(List.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256))
                .build();
    }

    private ByteArray userHandle(String userKey) {
        MfaUser u = store.getOrCreateUser(userKey);
        if (u.getUserHandle() != null) {
            try {
                return ByteArray.fromBase64Url(u.getUserHandle());
            } catch (Exception e) {
                throw new IllegalStateException("stored user handle is not base64url", e);
            }
        }
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        ByteArray handle = new ByteArray(raw);
        store.setUserHandle(userKey, handle.getBase64Url());
        return handle;
    }

    /** Starts a registration. Returns the request as stored JSON; see {@link #creationJson(String)}. */
    public String startRegistration(String userKey, String username, String displayName) {
        String rpId = rpId();
        PublicKeyCredentialCreationOptions options = relyingParty(rpId).startRegistration(StartRegistrationOptions.builder()
                .user(UserIdentity.builder().name(username).displayName(displayName).id(userHandle(userKey)).build())
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .residentKey(ResidentKeyRequirement.DISCOURAGED)
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .build())
                .timeout(120_000L)
                .build());
        // The library fills excludeCredentials by the display username, but the
        // repository is keyed by the Jira user key; set it from the key, so the
        // browser refuses an authenticator that is already registered.
        options = options.toBuilder().excludeCredentials(new Repository(rpId).getCredentialIdsForUsername(userKey)).build();
        try {
            return options.toJson();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** JSON for {@code navigator.credentials.create()}: {@code {"publicKey": {...}}}. */
    public static String creationJson(String storedRequest) throws IOException {
        return PublicKeyCredentialCreationOptions.fromJson(storedRequest).toCredentialsCreateJson();
    }

    public void finishRegistration(String userKey, String storedRequest, String responseJson, String label)
            throws IOException, RegistrationFailedException {
        PublicKeyCredentialCreationOptions request = PublicKeyCredentialCreationOptions.fromJson(storedRequest);
        // the ID the browser was asked for, also when the setting has changed since
        String rpId = request.getRp().getId();
        RegistrationResult result = relyingParty(rpId).finishRegistration(FinishRegistrationOptions.builder()
                .request(request)
                .response(PublicKeyCredential.parseRegistrationResponseJson(responseJson))
                .build());
        String credentialId = result.getKeyId().getId().getBase64Url();
        if (credentialId.length() > net.java.ao.schema.StringLength.MAX_LENGTH) {
            throw new IllegalArgumentException("credential ID of " + credentialId.length() + " characters is longer than the column");
        }
        store.addPasskey(userKey, credentialId, rpId, result.getPublicKeyCose().getBase64Url(),
                result.getSignatureCount(), label, System.currentTimeMillis());
    }

    /**
     * Starts an assertion for one relying party ID of the user's passkeys.
     * {@code requestHost} (may be null) only influences which of them.
     */
    public String startAssertion(String userKey, String requestHost) {
        Set<String> ids = store.passkeys(userKey).stream().map(this::effectiveRpId).collect(Collectors.toSet());
        AssertionRequest request = relyingParty(RelyingParties.chooseRpId(ids, requestHost, rpId())).startAssertion(StartAssertionOptions.builder()
                .username(userKey)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .timeout(120_000L)
                .build());
        try {
            return request.toJson();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String requestJson(String storedRequest) throws IOException {
        return AssertionRequest.fromJson(storedRequest).toCredentialsGetJson();
    }

    /** The challenge of a stored request, base64url. */
    public static String requestChallenge(String storedRequest) throws IOException {
        return AssertionRequest.fromJson(storedRequest).getPublicKeyCredentialRequestOptions().getChallenge().getBase64Url();
    }

    /** The challenge an assertion answers, base64url, or null if the response cannot be read. */
    public static String responseChallenge(String responseJson) {
        try {
            return PublicKeyCredential.parseAssertionResponseJson(responseJson).getResponse().getClientData()
                    .getChallenge().getBase64Url();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Verifies an assertion for {@code userKey}; returns true on success. */
    public boolean finishAssertion(String userKey, String storedRequest, String responseJson) throws IOException {
        AssertionRequest request = AssertionRequest.fromJson(storedRequest);
        try {
            String rpId = request.getPublicKeyCredentialRequestOptions().getRpId();
            AssertionResult result = relyingParty(rpId).finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(PublicKeyCredential.parseAssertionResponseJson(responseJson))
                    .build());
            if (!result.isSuccess() || !userKey.equals(result.getUsername())) {
                return false;
            }
            recordUse(userKey, result);
            return true;
        } catch (AssertionFailedException e) {
            return false;
        }
    }

    /** The assertion is valid; failing to record its use must not count as a failed attempt. */
    private void recordUse(String userKey, AssertionResult result) {
        try {
            store.updatePasskeyUse(result.getCredential().getCredentialId().getBase64Url(),
                    result.getSignatureCount(), System.currentTimeMillis());
        } catch (RuntimeException e) {
            LOG.error("cannot record the use of a passkey of {}", userKey, e);
        }
    }

    private final class Repository implements CredentialRepository {
        private final String rpId;

        Repository(String rpId) {
            this.rpId = rpId;
        }

        private boolean belongs(MfaPasskey p) {
            return rpId.equals(effectiveRpId(p));
        }

        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String userKey) {
            return store.passkeys(userKey).stream()
                    .filter(this::belongs)
                    .map(p -> PublicKeyCredentialDescriptor.builder().id(b64(p.getCredentialId())).build())
                    .collect(Collectors.toSet());
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String userKey) {
            return store.findUser(userKey).map(MfaUser::getUserHandle).map(PasskeyService::b64);
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
            return store.findUserByHandle(userHandle.getBase64Url()).map(MfaUser::getUserKey);
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
            Optional<String> owner = getUsernameForUserHandle(userHandle);
            if (!owner.isPresent()) {
                return Optional.empty();
            }
            return store.passkeysByCredentialId(credentialId.getBase64Url()).stream()
                    .filter(p -> p.getUserKey().equals(owner.get()) && belongs(p))
                    .findFirst()
                    .map(p -> toRegistered(p, userHandle));
        }

        /** Not limited to the relying party ID: a credential ID must be unique among all passkeys. */
        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            return store.passkeysByCredentialId(credentialId.getBase64Url()).stream()
                    .map(p -> toRegistered(p, getUserHandleForUsername(p.getUserKey()).orElse(new ByteArray(new byte[0]))))
                    .collect(Collectors.toSet());
        }
    }

    private static RegisteredCredential toRegistered(MfaPasskey p, ByteArray userHandle) {
        return RegisteredCredential.builder()
                .credentialId(b64(p.getCredentialId()))
                .userHandle(userHandle)
                .publicKeyCose(b64(p.getPublicKeyCose()))
                .signatureCount(p.getSignatureCount())
                .build();
    }

    static ByteArray b64(String s) {
        try {
            return ByteArray.fromBase64Url(s);
        } catch (Exception e) {
            throw new IllegalStateException("stored value is not base64url", e);
        }
    }
}
