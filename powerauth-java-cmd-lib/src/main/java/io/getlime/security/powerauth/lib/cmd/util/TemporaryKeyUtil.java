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
package io.getlime.security.powerauth.lib.cmd.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import io.getlime.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import io.getlime.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Helper class for fetching temporary keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class TemporaryKeyUtil {

    public static final String TEMPORARY_KEY_ID = "temporaryKeyId";
    public static final String TEMPORARY_PUBLIC_KEY = "temporaryPublicKey";

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();

    /**
     * Fetch temporary key for encryption from the server and store it into the step context.
     * @param step Current step.
     * @param stepContext Step context.
     * @param scope Encryption scope.
     * @throws Exception Thrown in case temporary key fetch fails.
     */
    public static void fetchTemporaryKey(PowerAuthStep step, StepContext<? extends BaseStepData, ?> stepContext, EncryptorScope scope) throws Exception {
        final PowerAuthVersion version = stepContext.getModel().getVersion();
        if (!version.useTemporaryKeys() || stepContext.getAttributes().containsKey(TEMPORARY_KEY_ID)) {
            stepContext.getAttributes().put(TEMPORARY_KEY_ID, null);
            return;
        }
        final RestClient restClient = RestClientFactory.getRestClient();
        if (restClient == null) {
            stepContext.getStepLogger().writeError(step.id() + "-error-rest-client", "Unable to prepare a REST client");
            return;
        }
        sendTemporaryKeyRequest(step, stepContext, scope);
    }

    private static Map<String, String> prepareHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

    private static String createJwtRequest(StepContext<? extends BaseStepData, ?> stepContext, BaseStepModel model, EncryptorScope scope, String challenge) throws Exception {
        final Instant now = Instant.now();
        final String activationId = scope == EncryptorScope.ACTIVATION_SCOPE ? model.getResultStatus().getActivationId() : null;
        final JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .claim("applicationKey", stepContext.getModel().toMap().get("APPLICATION_KEY"))
                .claim("activationId", activationId)
                .claim("challenge", challenge)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                .build();
        final byte[] secretKey = getSecretKey(stepContext, model, scope);
        return signJwt(jwtClaims, secretKey);
    }

    private static byte[] getSecretKey(StepContext<? extends BaseStepData, ?> stepContext, BaseStepModel model, EncryptorScope scope) throws Exception {
        final String appSecret = (String) stepContext.getModel().toMap().get("APPLICATION_SECRET");
        if (scope == EncryptorScope.APPLICATION_SCOPE) {
            return Base64.getDecoder().decode(appSecret);
        } else if (scope == EncryptorScope.ACTIVATION_SCOPE) {
            final byte[] appSecretBytes = Base64.getDecoder().decode(appSecret);
            final SecretKey transportMasterKey = model.getResultStatus().getTransportMasterKeyObject();
            final SecretKey secretKeyBytes = KEY_GENERATOR.deriveSecretKeyHmac(transportMasterKey, appSecretBytes);
            return KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKeyBytes);
        }
        return null;
    }

    private static String signJwt(JWTClaimsSet jwtClaims, byte[] secretKey) throws Exception {
        final JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        final byte[] payloadBytes = jwtClaims.toPayload().toBytes();
        final Base64URL encodedHeader = jwsHeader.toBase64URL();
        final Base64URL encodedPayload = Base64URL.encode(payloadBytes);
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] hash = new HMACHashUtilities().hash(secretKey, signingInput.getBytes(StandardCharsets.UTF_8));
        final Base64URL signature = Base64URL.encode(hash);
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    private static void sendTemporaryKeyRequest(PowerAuthStep step, StepContext<? extends BaseStepData, ?> stepContext, EncryptorScope scope) throws Exception {
        final BaseStepModel model = (BaseStepModel) stepContext.getModel();
        final Map<String, String> headers = prepareHeaders();
        final String uri = model.getUriString() + "/pa/v3/keystore/create";
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String requestData = createJwtRequest(stepContext, model, scope, challenge);
        final TemporaryKeyRequest jwtData = new TemporaryKeyRequest();
        jwtData.setJwt(requestData);
        final ObjectRequest<TemporaryKeyRequest> request = new ObjectRequest<>(jwtData);
        final RestClient restClient = RestClientFactory.getRestClient();
        try {
            final ObjectResponse<TemporaryKeyResponse> response = Objects.requireNonNull(restClient).postObject(uri, request, null, MapUtil.toMultiValueMap(headers), TemporaryKeyResponse.class);
            stepContext.getStepLogger().writeItem(step.id() + "-temporary-key-fetched", "Temporary key fetched", "Temporary key was fetched from the server", "OK", null);
            handleTemporaryKeyResponse(step, stepContext, response, scope);
        } catch (RestClientException ex) {
            stepContext.getStepLogger().writeServerCallError(step.id() + "-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
        }
    }

    private static void handleTemporaryKeyResponse(PowerAuthStep step, StepContext<? extends BaseStepData, ?> stepContext, ObjectResponse<TemporaryKeyResponse> response, EncryptorScope scope) throws Exception {
        final String jwtResponse = response.getResponseObject().getJwt();
        final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
        final ECPublicKey publicKey = switch (scope) {
            case ACTIVATION_SCOPE -> (ECPublicKey) stepContext.getModel().getResultStatus().getServerPublicKeyObject();
            case APPLICATION_SCOPE -> (ECPublicKey) stepContext.getModel().toMap().get("MASTER_PUBLIC_KEY");
        };
        if (!validateJwtSignature(decodedJWT, publicKey)) {
            stepContext.getStepLogger().writeError(step.id() + "-error-signature-invalid", "JWT signature is invalid");
            return;
        }
        final String temporaryKeyId = (String) decodedJWT.getJWTClaimsSet().getClaim("sub");
        final String temporaryPublicKey = (String) decodedJWT.getJWTClaimsSet().getClaim("publicKey");
        stepContext.getAttributes().put(TEMPORARY_KEY_ID, temporaryKeyId);
        stepContext.getAttributes().put(TEMPORARY_PUBLIC_KEY, temporaryPublicKey);
    }

    private static boolean validateJwtSignature(SignedJWT jwt, PublicKey publicKey) throws Exception {
        final Base64URL[] jwtParts = jwt.getParsedParts();
        final Base64URL encodedHeader = jwtParts[0];
        final Base64URL encodedPayload = jwtParts[1];
        final Base64URL encodedSignature = jwtParts[2];
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] signatureBytes = convertRawSignatureToDER(encodedSignature.decode());
        return SIGNATURE_UTILS.validateECDSASignature(signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes, publicKey);
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