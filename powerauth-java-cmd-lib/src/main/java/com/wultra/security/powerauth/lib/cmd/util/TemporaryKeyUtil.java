/*
 * PowerAuth Command-line utility
 * Copyright 2024 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.wultra.security.powerauth.lib.cmd.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.SharedSecretRequest;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.SharedSecretResponse;
import com.wultra.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import com.wultra.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Helper class for fetching temporary keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class TemporaryKeyUtil {

    private TemporaryKeyUtil() {
    }

    /**
     * Temporary key ID constant.
     */
    public static final String TEMPORARY_KEY_ID = "temporaryKeyId";

    /**
     * Temporary public key constant.
     */
    public static final String TEMPORARY_PUBLIC_KEY = "temporaryPublicKey";

    /**
     * Temporary client context for shared secret derivation.
     */
    public static final String TEMPORARY_CLIENT_CONTEXT = "temporaryClientContext";

    /**
     * Temporary shared secret constant.
     */
    public static final String TEMPORARY_SHARED_SECRET = "temporarySharedSecret";

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();

    private static final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private static final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();
    private static final ObjectMapper OBJECT_MAPPER = RestClientConfiguration.defaultMapper();

    /**
     * Fetch temporary key for encryption from the server and store it into the step context.
     * @param step Current step.
     * @param stepContext Step context.
     * @param scope Encryption scope.
     * @param algorithm Shared secret algorithm to use.
     * @throws Exception Thrown in case temporary key fetch fails.
     */
    public static void fetchTemporaryKey(PowerAuthStep step, StepContext<? extends BaseStepData, ?> stepContext, EncryptorScope scope, SharedSecretAlgorithm algorithm) throws Exception {
        final PowerAuthVersion version = stepContext.getModel().getVersion();
        if (!version.useTemporaryKeys() || stepContext.getAttributes().containsKey(TEMPORARY_KEY_ID)) {
            return;
        }
        final RestClient restClient = RestClientFactory.getRestClient();
        if (restClient == null) {
            stepContext.getStepLogger().writeError(step.id() + "-error-rest-client", "Unable to prepare a REST client");
            return;
        }
        sendTemporaryKeyRequest(step, stepContext, scope, algorithm);
    }

    private static Map<String, String> prepareHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

    private static String createJwtRequest(StepContext<? extends BaseStepData, ?> stepContext, BaseStepModel model, EncryptorScope scope, String challenge, SharedSecretAlgorithm algorithm) throws Exception {
        final Instant now = Instant.now();
        final String activationId = scope == EncryptorScope.ACTIVATION_SCOPE ? model.getResultStatus().getActivationId() : null;
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .claim("applicationKey", stepContext.getModel().toMap().get("APPLICATION_KEY"))
                .claim("activationId", activationId)
                .claim("challenge", challenge)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)));
        if (model.getVersion().getMajorVersion() == 4) {
            final SharedSecretRequest request = buildSharedSecretRequest(stepContext, algorithm);
            builder.claim("sharedSecretRequest", request);
            builder.build();
        }
        final JWTClaimsSet jwtClaims = builder.build();
        final byte[] secretKey = getSecretKey(stepContext, model, scope);
        return signJwt(jwtClaims, secretKey);
    }

    private static SharedSecretRequest buildSharedSecretRequest(StepContext<? extends BaseStepData, ?> stepContext, SharedSecretAlgorithm algorithm) throws GenericCryptoException {
        return switch (algorithm) {
            case EC_P384 -> {
                final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
                stepContext.getAttributes().put(TEMPORARY_CLIENT_CONTEXT, requestCryptogram.getSharedSecretClientContext());
                final SharedSecretRequestEcdhe requestEcdhe = (SharedSecretRequestEcdhe) requestCryptogram.getSharedSecretRequest();
                final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
                sharedSecretRequest.setAlgorithm(algorithm.toString());
                sharedSecretRequest.setEcdhe(requestEcdhe.getEcClientPublicKey());
                yield sharedSecretRequest;
            }
            case EC_P384_ML_L3 -> {
                final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID.generateRequestCryptogram();
                stepContext.getAttributes().put(TEMPORARY_CLIENT_CONTEXT, requestCryptogram.getSharedSecretClientContext());
                final SharedSecretRequestHybrid requestHybrid = (SharedSecretRequestHybrid) requestCryptogram.getSharedSecretRequest();
                final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
                sharedSecretRequest.setAlgorithm(algorithm.toString());
                sharedSecretRequest.setEcdhe(requestHybrid.getEcClientPublicKey());
                sharedSecretRequest.setMlkem(requestHybrid.getPqcEncapsulationKey());
                yield sharedSecretRequest;
            }
            default -> throw new IllegalStateException("Unsupported algorithm for version 4: " + algorithm);
        };
    }

    private static byte[] getSecretKey(StepContext<? extends BaseStepData, ?> stepContext, BaseStepModel model, EncryptorScope scope) throws Exception {
        final String appSecret = (String) stepContext.getModel().toMap().get("APPLICATION_SECRET");
        if (scope == EncryptorScope.APPLICATION_SCOPE) {
            return Base64.getDecoder().decode(appSecret);
        } else if (scope == EncryptorScope.ACTIVATION_SCOPE) {
            // TODO - change key derivation for crypto4
            final byte[] appSecretBytes = Base64.getDecoder().decode(appSecret);
            final SecretKey transportMasterKey = model.getResultStatus().getTransportMasterKeyObject();
            final SecretKey secretKeyBytes = KEY_GENERATOR.deriveSecretKeyHmac(transportMasterKey, appSecretBytes);
            return KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKeyBytes);
        }
        return null;
    }

    private static String signJwt(JWTClaimsSet jwtClaims, byte[] secretKey) throws Exception {
        // TODO - change to KMAC for crypto4
        final JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        final byte[] payloadBytes = jwtClaims.toPayload().toBytes();
        final Base64URL encodedHeader = jwsHeader.toBase64URL();
        final Base64URL encodedPayload = Base64URL.encode(payloadBytes);
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] hash = new HMACHashUtilities().hash(secretKey, signingInput.getBytes(StandardCharsets.UTF_8));
        final Base64URL signature = Base64URL.encode(hash);
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    private static void sendTemporaryKeyRequest(PowerAuthStep step, StepContext<? extends BaseStepData, ?> stepContext, EncryptorScope scope, SharedSecretAlgorithm algorithm) throws Exception {
        final BaseStepModel model = (BaseStepModel) stepContext.getModel();
        final Map<String, String> headers = prepareHeaders();
        String baseUri = model.getBaseUriString();
        if (!StringUtils.hasText(baseUri)) {
            baseUri = model.getUriString();
            if (!StringUtils.hasText(baseUri)) {
                stepContext.getStepLogger().writeError(step.id() + "-error-missing-base-uri-string", "Base URI string is required for fetching temporary keys");
                return;
            }
        }
        String uri = baseUri + "/pa/v" + model.getVersion().getMajorVersion() + "/keystore/create";
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String requestData = createJwtRequest(stepContext, model, scope, challenge, algorithm);
        final TemporaryKeyRequest jwtData = new TemporaryKeyRequest();
        jwtData.setJwt(requestData);
        final ObjectRequest<TemporaryKeyRequest> request = new ObjectRequest<>(jwtData);
        final RestClient restClient = RestClientFactory.getRestClient();
        try {
            final ObjectResponse<TemporaryKeyResponse> response = Objects.requireNonNull(restClient).postObject(uri, request, null, MapUtil.toMultiValueMap(headers), TemporaryKeyResponse.class);
            stepContext.getStepLogger().writeItem(step.id() + "-temporary-key-fetched", "Temporary key fetched", "Temporary key was fetched from the server", "OK", null);
            handleTemporaryKeyResponse(step, stepContext, response, scope, algorithm);
        } catch (RestClientException ex) {
            stepContext.getStepLogger().writeServerCallError(step.id() + "-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
        }
    }

    private static void handleTemporaryKeyResponse(PowerAuthStep step, StepContext<? extends BaseStepData, ?> stepContext, ObjectResponse<TemporaryKeyResponse> response, EncryptorScope scope, SharedSecretAlgorithm algorithm) throws Exception {
        final BaseStepModel model = (BaseStepModel) stepContext.getModel();
        final String jwtResponse = response.getResponseObject().getJwt();
        final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
        final ECPublicKey publicKey = switch (scope) {
            case ACTIVATION_SCOPE -> (ECPublicKey) stepContext.getModel().getResultStatus().getServerPublicKeyObject();
            case APPLICATION_SCOPE -> (ECPublicKey) stepContext.getModel().toMap().get("MASTER_PUBLIC_KEY");
        };
        if (scope == EncryptorScope.APPLICATION_SCOPE && model.getVersion().getMajorVersion() == 4) {
            // TODO - signature verification is skipped for crypto4 because master public key is not configured for P-384 curve yet
        } else if (!validateJwtSignature(decodedJWT, publicKey, model.getVersion())) {
            stepContext.getStepLogger().writeError(step.id() + "-error-signature-invalid", "JWT signature is invalid");
            return;
        }
        final String temporaryKeyId = (String) decodedJWT.getJWTClaimsSet().getClaim("sub");
        stepContext.getAttributes().put(TEMPORARY_KEY_ID, temporaryKeyId);
        switch (model.getVersion().getMajorVersion()) {
            case 3 -> handlePublicKeyResponse(stepContext, decodedJWT);
            case 4 -> handleSharedSecretResponse(stepContext, decodedJWT, algorithm);
            default -> throw new IllegalStateException("Unsupported version" + model.getVersion());
        }
    }

    private static void handlePublicKeyResponse(StepContext<? extends BaseStepData, ?> stepContext, SignedJWT decodedJWT) throws ParseException {
        final String temporaryPublicKey = (String) decodedJWT.getJWTClaimsSet().getClaim("publicKey");
        stepContext.getAttributes().put(TEMPORARY_PUBLIC_KEY, temporaryPublicKey);
    }

    private static void handleSharedSecretResponse(StepContext<? extends BaseStepData, ?> stepContext, SignedJWT decodedJWT, SharedSecretAlgorithm algorithm) throws ParseException, GenericCryptoException {
        final Object claim = decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final SecretKey sharedSecret = switch (algorithm) {
            case EC_P384 -> {
                SharedSecretClientContextEcdhe clientContext = (SharedSecretClientContextEcdhe) stepContext.getAttributes().get(TEMPORARY_CLIENT_CONTEXT);
                final SharedSecretResponseEcdhe sharedSecretResponseEcdhe = new SharedSecretResponseEcdhe();
                sharedSecretResponseEcdhe.setEcServerPublicKey(serverResponse.getEcdhe());
                yield SHARED_SECRET_ECDHE.computeSharedSecret(clientContext, sharedSecretResponseEcdhe);
            }
            case EC_P384_ML_L3 -> {
                SharedSecretClientContextHybrid clientContext = (SharedSecretClientContextHybrid) stepContext.getAttributes().get(TEMPORARY_CLIENT_CONTEXT);
                final SharedSecretResponseHybrid sharedSecretResponseHybrid = new SharedSecretResponseHybrid();
                sharedSecretResponseHybrid.setEcServerPublicKey(serverResponse.getEcdhe());
                sharedSecretResponseHybrid.setPqcEncapsulation(serverResponse.getMlkem());
                yield SHARED_SECRET_HYBRID.computeSharedSecret(clientContext, sharedSecretResponseHybrid);
            }
            default -> throw new IllegalStateException("Unsupported algorithm for version 4: " + algorithm);
        };
        stepContext.getAttributes().put(TEMPORARY_SHARED_SECRET, sharedSecret);
        stepContext.getAttributes().remove(TEMPORARY_CLIENT_CONTEXT);
    }

    private static boolean validateJwtSignature(SignedJWT jwt, PublicKey publicKey, PowerAuthVersion version) throws Exception {
        final Base64URL[] jwtParts = jwt.getParsedParts();
        final Base64URL encodedHeader = jwtParts[0];
        final Base64URL encodedPayload = jwtParts[1];
        final Base64URL encodedSignature = jwtParts[2];
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] signatureBytes = convertRawSignatureToDER(encodedSignature.decode());
        return switch (version.getMajorVersion()) {
            case 3:
                yield SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes, publicKey);
            case 4:
                yield SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes, publicKey);
            default:
                throw new IllegalStateException("Unsupported version: " + version);
        };
    }

    private static byte[] convertRawSignatureToDER(byte[] rawSignature) throws Exception {
        if (rawSignature.length % 2 != 0) {
            throw new IllegalArgumentException("Invalid ECDSA signature format");
        }
        int len = rawSignature.length / 2;
        byte[] rBytes = new byte[len];
        byte[] sBytes = new byte[len];
        System.arraycopy(rawSignature, 0, rBytes, 0, len);
        System.arraycopy(rawSignature, len, sBytes, 0, len);
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DLSequence(v).getEncoded();
    }

}