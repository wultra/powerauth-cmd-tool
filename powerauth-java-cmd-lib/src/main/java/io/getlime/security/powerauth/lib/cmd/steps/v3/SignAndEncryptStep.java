/*
 * PowerAuth Command-line utility
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.lib.cmd.steps.v3;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Sign and encrypt step signs request data and performs encryption using ECIES encryption in activation scope.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SignAndEncryptStep implements BaseStep {

    private static final KeyConvertor keyConvertor = new KeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();
    private static final EciesFactory eciesFactory = new EciesFactory();

    /**
     * Execute this step with given context.
     * @param stepLogger Step logger.
     * @param context Provided context.
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "sign-encrypt-start",
                    "Sign and Encrypt Request Started",
                    null,
                    "OK",
                    null
            );
        }

        // Verify that HTTP method is set
        if (model.getHttpMethod() == null) {
            if (stepLogger != null) {
                stepLogger.writeError("sign-encrypt-error-http-method", "HTTP method not specified", "Specify HTTP method to use for sending request");
                stepLogger.writeDoneFailed("sign-encrypt-failed");
            }
            return null;
        }

        // Verify HTTP method, only POST is supported
        if (!"POST".equals(model.getHttpMethod().toUpperCase())) {
            if (stepLogger != null) {
                stepLogger.writeError("sign-encrypt-error-http-method-invalid", "Sign and Encrypt Request Failed", "Unsupported HTTP method: "+model.getHttpMethod().toUpperCase());
                stepLogger.writeDoneFailed("sign-encrypt-failed");
            }
            return null;
        }

        // Prepare the encryption URI
        String uri = model.getUriString();

        // Read data which needs to be encrypted
        final byte[] requestDataBytes = model.getData();
        if (requestDataBytes == null) {
            if (stepLogger != null) {
                stepLogger.writeError("sign-encrypt-error-file", "Sign and Encrypt Request Failed", "Request data for encryption and signing is null.");
                stepLogger.writeDoneFailed("sign-encrypt-failed");
            }
            return null;
        }


        if (stepLogger != null) {
            stepLogger.writeItem(
                    "sign-encrypt-request-prepare",
                    "Preparing Request Data",
                    "Following data will be encrypted",
                    "OK",
                    requestDataBytes
            );
        }

        // Get data from status
        String activationId = JsonUtil.stringValue(model.getResultStatusObject(), "activationId");
        long counter = JsonUtil.longValue(model.getResultStatusObject(), ("counter"));
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signaturePossessionKey"));
        byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureBiometryKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureKnowledgeKeyEncrypted"));

        char[] password = VerifySignatureUtil.getKnowledgeKeyPassword(model);

        // Get the signature keys
        SecretKey signaturePossessionKey = keyConvertor.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signatureBiometryKey = keyConvertor.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

        // Generate nonce
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);

        // Construct the signature base string data
        byte[] dataFileBytes = VerifySignatureUtil.extractRequestDataBytes(model, stepLogger);

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(model.getHttpMethod().toUpperCase(), model.getResourceId(), nonceBytes, dataFileBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion());
        String signatureValue = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData, signatureFormat);
        final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), signatureValue, model.getSignatureType().toString(), BaseEncoding.base64().encode(nonceBytes), model.getVersion());
        String httpAuthorizationHeader = header.buildHttpHeader();

        // Increment the counter
        CounterUtil.incrementCounter(model);

        // Store the activation status (updated counter)
        String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
        try (FileWriter file = new FileWriter(model.getStatusFileName())) {
            file.write(formatted);
        }

        final String transportKeyBase64 = JsonUtil.stringValue(model.getResultStatusObject(), "transportMasterKey");
        final String serverPublicKeyBase64 = JsonUtil.stringValue(model.getResultStatusObject(), "serverPublicKey");

        // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/activation
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        final byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(transportKeyBase64);
        final byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(serverPublicKeyBase64);
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                        transportMasterKeyBytes, EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC);

        if (stepLogger != null) {

            Map<String, String> lowLevelData = new HashMap<>();
            lowLevelData.put("counter", String.valueOf(counter));
            int version = JsonUtil.intValue(model.getResultStatusObject(), "version");
            if (version == 3) {
                lowLevelData.put("ctrData", BaseEncoding.base64().encode(ctrData));
            }
            lowLevelData.put("signatureBaseString", signatureBaseString);
            lowLevelData.put("resourceId", model.getResourceId());
            lowLevelData.put("nonce", BaseEncoding.base64().encode(nonceBytes));
            lowLevelData.put("applicationKey", model.getApplicationKey());
            lowLevelData.put("applicationSecret", model.getApplicationSecret());
            lowLevelData.put("transportKey", transportKeyBase64);
            lowLevelData.put("serverPublicKey", serverPublicKeyBase64);
            lowLevelData.put("activationId", activationId);

            stepLogger.writeItem(
                    "sign-encrypt-signature-computed",
                    "Signature Calculation Parameters",
                    "Low level cryptographic inputs required to compute signature and keys used for data encryption.",
                    "OK",
                    lowLevelData
            );
        }

        // Prepare encrypted request
        final boolean useIv = !"3.0".equals(model.getVersion());
        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest(requestDataBytes, useIv);
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        final String ephemeralPublicKeyBase64 = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());
        final String encryptedData = BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData());
        final String mac = BaseEncoding.base64().encode(eciesCryptogram.getMac());
        final String nonce = useIv ? BaseEncoding.base64().encode(eciesCryptogram.getNonce()) : null;
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);

        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "sign-encrypt-request-encrypt",
                    "Encrypting Request Data",
                    "Following data is sent to intermediate server",
                    "OK",
                    request
            );
        }
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, httpAuthorizationHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall("sign-encrypt-request-sent", model.getUriString(), model.getHttpMethod().toUpperCase(), new String(dataFileBytes, StandardCharsets.UTF_8), headers);
            }

            ResponseEntity<EciesEncryptedResponse> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            ParameterizedTypeReference<EciesEncryptedResponse> typeReference = new ParameterizedTypeReference<EciesEncryptedResponse>() {};
            try {
                responseEntity = restClient.post(uri, requestBytes, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError("sign-encrypt-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                    stepLogger.writeDoneFailed("sign-encrypt-failed");
                }
                return null;
            }

            EciesEncryptedResponse encryptedResponse = Objects.requireNonNull(responseEntity.getBody());

            if (stepLogger != null) {
                stepLogger.writeServerCallOK("sign-encrypt-response-received", encryptedResponse, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));
            }

            byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
            byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
            EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

            final byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

            String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
            model.getResultStatusObject().put("responseData", decryptedMessage);

            if (stepLogger != null) {
                stepLogger.writeItem(
                        "sign-encrypt-response-decrypted",
                        "Decrypted Response",
                        "Following data were decrypted",
                        "OK",
                        decryptedMessage
                );
                stepLogger.writeDoneOK("sign-encrypt-success");
            }
            return model.getResultStatusObject();
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError("sign-encrypt-error-generic", exception);
                stepLogger.writeDoneFailed("sign-encrypt-failed");
            }
            return null;
        }
    }

}
