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
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
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
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.ActivationData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.AuthorizationHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.request.RequestSharedSecret;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.request.RequestSharedSecretEcdhe;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.request.RequestSharedSecretHybrid;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.response.ResponseSharedSecretEcdhe;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.response.ResponseSharedSecretHybrid;
import com.wultra.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import com.wultra.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import lombok.Data;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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
    private static final PqcDsa PQC_DSA = new PqcDsa();

    private static final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private static final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();
    private static final ObjectMapper OBJECT_MAPPER = RestClientConfiguration.defaultMapper();

    private static final JSONParser JSON_PARSER = new JSONParser();

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
                .claim("applicationKey", getApplicationKey(stepContext))
                .claim("activationId", activationId)
                .claim("challenge", challenge)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)));
        if (model.getVersion().getMajorVersion() == 4) {
            final RequestSharedSecret request = buildSharedSecretRequest(stepContext, algorithm);
            builder.claim("sharedSecretRequest", request);
            builder.build();
        }
        final JWTClaimsSet jwtClaims = builder.build();
        final byte[] signingKey = getSigningKey(stepContext, model, scope);
        return signJwt(jwtClaims, signingKey);
    }

    private static RequestSharedSecret buildSharedSecretRequest(StepContext<? extends BaseStepData, ?> stepContext, SharedSecretAlgorithm algorithm) throws GenericCryptoException {
        return switch (algorithm) {
            case EC_P384 -> {
                final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
                stepContext.getAttributes().put(TEMPORARY_CLIENT_CONTEXT, requestCryptogram.getSharedSecretClientContext());
                final SharedSecretRequestEcdhe requestEcdhe = (SharedSecretRequestEcdhe) requestCryptogram.getSharedSecretRequest();
                final RequestSharedSecretEcdhe sharedSecretRequest = new RequestSharedSecretEcdhe();
                sharedSecretRequest.setAlgorithm(algorithm.toString());
                sharedSecretRequest.setEcdhe(requestEcdhe.getEcClientPublicKey());
                yield sharedSecretRequest;
            }
            case EC_P384_ML_L3 -> {
                final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID.generateRequestCryptogram();
                stepContext.getAttributes().put(TEMPORARY_CLIENT_CONTEXT, requestCryptogram.getSharedSecretClientContext());
                final SharedSecretRequestHybrid requestHybrid = (SharedSecretRequestHybrid) requestCryptogram.getSharedSecretRequest();
                final RequestSharedSecretHybrid sharedSecretRequest = new RequestSharedSecretHybrid();
                sharedSecretRequest.setAlgorithm(algorithm.toString());
                sharedSecretRequest.setEcdhe(requestHybrid.getEcClientPublicKey());
                sharedSecretRequest.setMlkem(requestHybrid.getPqcEncapsulationKey());
                yield sharedSecretRequest;
            }
            default -> throw new IllegalStateException("Unsupported algorithm for version 4: " + algorithm);
        };
    }

    private static byte[] getSigningKey(StepContext<? extends BaseStepData, ?> stepContext, BaseStepModel model, EncryptorScope scope) throws Exception {
        final String appSecret = getApplicationSecret(stepContext);
        final byte[] appSecretBytes = Base64.getDecoder().decode(appSecret);
        return switch (model.getVersion().getMajorVersion()) {
            case 3 -> switch (scope) {
                case APPLICATION_SCOPE -> appSecretBytes;
                case ACTIVATION_SCOPE -> {
                    final SecretKey transportMasterKey = model.getResultStatus().getTransportMasterKeyObject();
                    final SecretKey secretKeyBytes = KEY_GENERATOR.deriveSecretKeyHmac(transportMasterKey, appSecretBytes);
                    yield KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKeyBytes);
                }
            };
            case 4 -> switch (scope) {
                case APPLICATION_SCOPE -> {
                    final SecretKey sourceKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(appSecretBytes);
                    final SecretKey secretKey = KeyFactory.deriveKeyMacGetAppTempKey(sourceKey);
                    yield KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKey);
                }
                case ACTIVATION_SCOPE -> {
                    final String tempKeyActSignBase64 = model.getResultStatus().getTemporaryKeyActSignRequestKey();
                    final byte[] tempKeyActSignBytes = Base64.getDecoder().decode(tempKeyActSignBase64);
                    final SecretKey secretKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(tempKeyActSignBytes);
                    yield KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKey);
                }
            };
            default -> throw new IllegalStateException("Unsupported version: " + model.getVersion());
        };
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
        final String temporaryKeyId;
        switch (model.getVersion().getMajorVersion()) {
            case 3 -> {
                final PublicKey publicKey = switch (scope) {
                    case ACTIVATION_SCOPE -> (ECPublicKey) stepContext.getModel().getResultStatus().getEcServerPublicKeyObject();
                    case APPLICATION_SCOPE -> getEcMasterPublicKey(stepContext, algorithm);
                };
                final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
                handlePublicKeyResponse(stepContext, decodedJWT.getJWTClaimsSet());
                if (!validateJwtSignature(decodedJWT, publicKey, algorithm)) {
                    stepContext.getStepLogger().writeError(step.id() + "-error-signature-invalid", "JWT signature is invalid");
                    return;
                }
                temporaryKeyId = (String) decodedJWT.getJWTClaimsSet().getClaim("sub");
            }
            case 4 -> {
                final Map<String, JwtSignatureData> signatureData = extractSignatureData(jwtResponse);
                if (signatureData.get("ES384") == null) {
                    throw new IllegalStateException("Missing EC signature for algorithm: " + algorithm);
                }
                if (algorithm == SharedSecretAlgorithm.EC_P384_ML_L3 && signatureData.get("ML-DSA-65") == null) {
                    throw new IllegalStateException("Missing ML-DSA signature for algorithm: " + algorithm);
                }
                final JWTClaimsSet claims = extractClaims(jwtResponse);
                handleSharedSecretResponse(stepContext, claims, algorithm);
                final Map<String, PublicKey> publicKeys = new HashMap<>();
                switch (algorithm) {
                    case EC_P384 -> {
                        switch (scope) {
                            case ACTIVATION_SCOPE -> publicKeys.put("ES384", stepContext.getModel().getResultStatus().getEcServerPublicKeyObject());
                            case APPLICATION_SCOPE -> publicKeys.put("ES384", getEcMasterPublicKey(stepContext, algorithm));
                        }
                    }
                    case EC_P384_ML_L3 -> {
                        switch (scope) {
                            case ACTIVATION_SCOPE -> {
                                publicKeys.put("ES384", stepContext.getModel().getResultStatus().getEcServerPublicKeyObject());
                                publicKeys.put("ML-DSA-65", stepContext.getModel().getResultStatus().getPqcServerPublicKeyObject());
                            }
                            case APPLICATION_SCOPE -> {
                                publicKeys.put("ES384", getEcMasterPublicKey(stepContext, algorithm));
                                publicKeys.put("ML-DSA-65", getMlDsaMasterPublicKey(stepContext));
                            }
                        }
                    }
                    default -> throw new IllegalStateException("Unsupported algorithm: " + algorithm);
                }

                if (!validateHybridSignatures(signatureData, publicKeys, algorithm)) {
                    stepContext.getStepLogger().writeError(step.id() + "-error-signature-invalid", "JWT signature is invalid");
                    return;
                }
                temporaryKeyId = claims.getStringClaim("sub");
            }
            default -> throw new IllegalStateException("Unsupported version" + model.getVersion());
        }
        stepContext.getAttributes().put(TEMPORARY_KEY_ID, temporaryKeyId);
    }

    private static Map<String, JwtSignatureData> extractSignatureData(String jwtJson) throws ParseException {
        final JSONObject jwtObject = (JSONObject) JSON_PARSER.parse(jwtJson);
        final JSONArray signatures = (JSONArray) jwtObject.get("signatures");
        final String payloadB64 = (String) jwtObject.get("payload");
        final Map<String, JwtSignatureData> result = new HashMap<>();
        for (Object sigObj : signatures) {
            final JSONObject sigEntry = (JSONObject) sigObj;
            final String protectedB64 = (String) sigEntry.get("protected");
            final String signatureB64 = (String) sigEntry.get("signature");
            final String protectedJson = new String(Base64.getUrlDecoder().decode(protectedB64), StandardCharsets.UTF_8);
            final JSONObject protectedHeader = (JSONObject) JSON_PARSER.parse(protectedJson);
            final String alg = (String) protectedHeader.get("alg");
            final String signingInput = protectedB64 + "." + payloadB64;
            result.put(alg, new JwtSignatureData(signatureB64, signingInput));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static JWTClaimsSet extractClaims(String jwtJson) throws java.text.ParseException, ParseException {
        JSONObject jwtObject = (JSONObject) JSON_PARSER.parse(jwtJson);
        String payloadBase64 = (String) jwtObject.get("payload");
        String payloadJson = new String(Base64.getUrlDecoder().decode(payloadBase64), StandardCharsets.UTF_8);
        final JSONObject payload = (JSONObject) JSON_PARSER.parse(payloadJson);
        return JWTClaimsSet.parse(payload);
    }

    private static void handlePublicKeyResponse(StepContext<? extends BaseStepData, ?> stepContext, JWTClaimsSet claims) {
        final String temporaryPublicKey = (String) claims.getClaim("publicKey");
        stepContext.getAttributes().put(TEMPORARY_PUBLIC_KEY, temporaryPublicKey);
    }

    private static void handleSharedSecretResponse(StepContext<? extends BaseStepData, ?> stepContext, JWTClaimsSet claims, SharedSecretAlgorithm algorithm) throws GenericCryptoException {
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SecretKey sharedSecret = switch (algorithm) {
            case EC_P384 -> {
                final ResponseSharedSecretEcdhe serverResponse = OBJECT_MAPPER.convertValue(claim, ResponseSharedSecretEcdhe.class);
                final SharedSecretClientContextEcdhe clientContext = (SharedSecretClientContextEcdhe) stepContext.getAttributes().get(TEMPORARY_CLIENT_CONTEXT);
                final SharedSecretResponseEcdhe sharedSecretResponseEcdhe = new SharedSecretResponseEcdhe();
                sharedSecretResponseEcdhe.setEcServerPublicKey(serverResponse.getEcdhe());
                yield SHARED_SECRET_ECDHE.computeSharedSecret(clientContext, sharedSecretResponseEcdhe);
            }
            case EC_P384_ML_L3 -> {
                final ResponseSharedSecretHybrid serverResponse = OBJECT_MAPPER.convertValue(claim, ResponseSharedSecretHybrid.class);
                final SharedSecretClientContextHybrid clientContext = (SharedSecretClientContextHybrid) stepContext.getAttributes().get(TEMPORARY_CLIENT_CONTEXT);
                final SharedSecretResponseHybrid sharedSecretResponseHybrid = new SharedSecretResponseHybrid();
                sharedSecretResponseHybrid.setEcServerPublicKey(serverResponse.getEcdhe());
                sharedSecretResponseHybrid.setPqcCiphertext(serverResponse.getMlkem());
                yield SHARED_SECRET_HYBRID.computeSharedSecret(clientContext, sharedSecretResponseHybrid);
            }
            default -> throw new IllegalStateException("Unsupported algorithm for version 4: " + algorithm);
        };
        stepContext.getAttributes().put(TEMPORARY_SHARED_SECRET, sharedSecret);
        stepContext.getAttributes().remove(TEMPORARY_CLIENT_CONTEXT);
    }

    private static boolean validateHybridSignatures(Map<String, JwtSignatureData> signatureData, Map<String, PublicKey> publicKeys, SharedSecretAlgorithm algorithm) throws IOException, GenericCryptoException, InvalidKeyException, CryptoProviderException {
        if (algorithm != SharedSecretAlgorithm.EC_P384 && algorithm != SharedSecretAlgorithm.EC_P384_ML_L3) {
            return false;
        }
        final JwtSignatureData signatureEc = signatureData.get("ES384");
        final byte[] signingInputEc = signatureEc.getSigningInput().getBytes(StandardCharsets.UTF_8);
        final byte[] signatureEcBytes = convertRawSignatureToDER(Base64URL.from(signatureEc.getSignature()).decode());
        final PublicKey publicKeyEc = publicKeys.get("ES384");
        boolean signaturesValid = validateEcSignature(signingInputEc, signatureEcBytes, publicKeyEc, algorithm);
        if (algorithm == SharedSecretAlgorithm.EC_P384_ML_L3) {
            final PublicKey publicKeyMlDsa = publicKeys.get("ML-DSA-65");
            final JwtSignatureData signatureMlDsa = signatureData.get("ML-DSA-65");
            final byte[] signingInputMlDsa = signatureMlDsa.getSigningInput().getBytes(StandardCharsets.UTF_8);
            final byte[] signatureMlDsaBytes = Base64URL.from(signatureMlDsa.getSignature()).decode();
            signaturesValid = signaturesValid && PQC_DSA.verify(publicKeyMlDsa, signingInputMlDsa, signatureMlDsaBytes);
        }
        return signaturesValid;
    }

    private static boolean validateJwtSignature(SignedJWT jwt, PublicKey publicKey, SharedSecretAlgorithm algorithm) throws IOException, GenericCryptoException, InvalidKeyException, CryptoProviderException {
        final Base64URL[] jwtParts = jwt.getParsedParts();
        final Base64URL encodedHeader = jwtParts[0];
        final Base64URL encodedPayload = jwtParts[1];
        final Base64URL encodedSignature = jwtParts[2];
        final byte[] signingInput = (encodedHeader + "." + encodedPayload).getBytes(StandardCharsets.UTF_8);
        final byte[] signatureBytes = convertRawSignatureToDER(encodedSignature.decode());
        return validateEcSignature(signingInput, signatureBytes, publicKey, algorithm);
    }

    private static boolean validateEcSignature(byte[] signingInput, byte[] signatureBytes, PublicKey publicKey, SharedSecretAlgorithm algorithm) throws GenericCryptoException, InvalidKeyException, CryptoProviderException {
        return switch (algorithm) {
            case EC_P256 -> SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, signingInput, signatureBytes, publicKey);
            case EC_P384, EC_P384_ML_L3 -> SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, signingInput, signatureBytes, publicKey);
        };
    }

    private static byte[] convertRawSignatureToDER(byte[] rawSignature) throws IOException {
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

    private static String getApplicationKey(StepContext<? extends BaseStepData, ?> stepContext) {
        if (stepContext.getModel() instanceof AuthorizationHeaderData authenticationModel) {
            return authenticationModel.getApplicationKey();
        } else if (stepContext.getModel() instanceof EncryptionHeaderData encryptionModel) {
            return encryptionModel.getApplicationKey();
        }
        throw new IllegalStateException("Invalid model for obtaining application key");
    }

    private static String getApplicationSecret(StepContext<? extends BaseStepData, ?> stepContext) {
        if (stepContext.getModel() instanceof AuthorizationHeaderData signatureModel) {
            return signatureModel.getApplicationSecret();
        } else if (stepContext.getModel() instanceof EncryptionHeaderData encryptionModel) {
            return encryptionModel.getApplicationSecret();
        }
        throw new IllegalStateException("Invalid model for obtaining application secret");
    }

    private static PublicKey getEcMasterPublicKey(StepContext<? extends BaseStepData, ?> stepContext, SharedSecretAlgorithm algorithm) {
        if (stepContext.getModel() instanceof ActivationData activationModel) {
            return switch (algorithm) {
                case EC_P256 -> activationModel.getMasterPublicKeyP256();
                case EC_P384, EC_P384_ML_L3 -> activationModel.getMasterPublicKeyP384();
            };
        } else if (stepContext.getModel() instanceof EncryptStepModel encryptionModel) {
            return switch (algorithm) {
                case EC_P256 -> encryptionModel.getMasterPublicKeyP256();
                case EC_P384, EC_P384_ML_L3 -> encryptionModel.getMasterPublicKeyP384();
            };
        }
        throw new IllegalStateException("Invalid model for obtaining ECDSA master public key");
    }

    private static PublicKey getMlDsaMasterPublicKey(StepContext<? extends BaseStepData, ?> stepContext) {
        if (stepContext.getModel() instanceof ActivationData activationModel) {
            return activationModel.getMasterPublicKeyMlDsa65();
        } else if (stepContext.getModel() instanceof EncryptStepModel encryptionModel) {
            return encryptionModel.getMasterPublicKeyMlDsa65();
        }
        throw new IllegalStateException("Invalid model for obtaining ML-DSA master public key");
    }

    @Data
    private static class JwtSignatureData {

        public final String signature;
        public final String signingInput;

    }

}