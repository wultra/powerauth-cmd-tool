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
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * Sign and encrypt step signs request data and performs encryption using ECIES encryption in activation scope.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class SignAndEncryptStep implements BaseStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
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
                    "Sign and Encrypt Request Started",
                    null,
                    "OK",
                    null
            );
        }

        // Read data which needs to be encrypted
        File dataFile = new File(model.getDataFileName());
        if (!dataFile.exists()) {
            if (stepLogger != null) {
                stepLogger.writeError("Sign and Encrypt Request Failed", "File not found: " + model.getDataFileName());
                stepLogger.writeDoneFailed();
            }
            return null;
        }

        // Verify that HTTP method is set
        if (model.getHttpMethod() == null) {
            if (stepLogger != null) {
                stepLogger.writeError("HTTP method not specified", "Specify HTTP method to use for sending request");
                stepLogger.writeDoneFailed();
            }
            return null;
        }

        // Verify HTTP method, only POST is supported
        if (!"POST".equals(model.getHttpMethod().toUpperCase())) {
            if (stepLogger != null) {
                stepLogger.writeError("Sign and Encrypt Request Failed", "Unsupported HTTP method: "+model.getHttpMethod().toUpperCase());
                stepLogger.writeDoneFailed();
            }
            return null;
        }

        Scanner scanner = new Scanner(dataFile, "UTF-8");
        scanner.useDelimiter("\\Z");
        String requestData = "";
        if (scanner.hasNext()) {
            requestData = scanner.next();
        }

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Preparing Request Data",
                    "Following data will be encrypted",
                    "OK",
                    requestData
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
        SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signatureBiometryKey = keyConversion.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        // Construct the signature base string data
        byte[] dataFileBytes = VerifySignatureUtil.extractRequestDataBytes(model, stepLogger);

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(model.getHttpMethod().toUpperCase(), model.getResourceId(), pa_nonce, dataFileBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        String pa_signature = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData);
        final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), pa_signature, model.getSignatureType().toString(), BaseEncoding.base64().encode(pa_nonce), model.getVersion());
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
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConversion.convertBytesToPublicKey(serverPublicKeyBytes);
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
            lowLevelData.put("nonce", BaseEncoding.base64().encode(pa_nonce));
            lowLevelData.put("applicationKey", model.getApplicationKey());
            lowLevelData.put("applicationSecret", model.getApplicationSecret());
            lowLevelData.put("transportKey", transportKeyBase64);
            lowLevelData.put("serverPublicKey", serverPublicKeyBase64);
            lowLevelData.put("activationId", activationId);

            stepLogger.writeItem(
                    "Signature Calculation Parameters",
                    "Low level cryptographic inputs required to compute signature and keys used for data encryption.",
                    "OK",
                    lowLevelData
            );
        }

        // Prepare encrypted request
        byte[] requestDataBytes = requestData.getBytes(StandardCharsets.UTF_8);
        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest(requestDataBytes);
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        final String ephemeralPublicKeyBase64 = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());
        final String encryptedData = BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData());
        final String mac = BaseEncoding.base64().encode(eciesCryptogram.getMac());
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);

        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        if (stepLogger != null) {
            stepLogger.writeItem(
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
                stepLogger.writeServerCall(model.getUriString(), model.getHttpMethod().toUpperCase(), new String(dataFileBytes, StandardCharsets.UTF_8), headers);
            }

            HttpResponse response = Unirest.post(model.getUriString())
                        .headers(headers)
                        .body(requestBytes)
                        .asString();

            if (response.getStatus() == 200) {
                EciesEncryptedResponse encryptedResponse = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getRawBody(), EciesEncryptedResponse.class);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(encryptedResponse, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
                byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
                EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

                final byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

                String decryptedMessage = new String(decryptedBytes);
                model.getResultStatusObject().put("responseData", decryptedMessage);

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Decrypted Response",
                            "Following data were decrypted",
                            "OK",
                            decryptedMessage
                    );
                    stepLogger.writeDoneOK();
                }
                return model.getResultStatusObject();
            } else {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError(response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                    stepLogger.writeDoneFailed();
                }
                return null;
            }
        } catch (UnirestException exception) {
            if (stepLogger != null) {
                stepLogger.writeServerCallConnectionError(exception);
                stepLogger.writeDoneFailed();
            }
            return null;
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError(exception);
                stepLogger.writeDoneFailed();
            }
            return null;
        }
    }

}
