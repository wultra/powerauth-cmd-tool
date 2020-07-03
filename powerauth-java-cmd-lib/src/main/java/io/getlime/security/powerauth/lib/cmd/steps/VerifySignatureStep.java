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
package io.getlime.security.powerauth.lib.cmd.steps;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.util.*;
import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Helper class with signature verification logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Petr Dvorak
 *
 */
public class VerifySignatureStep implements BaseStep {

    private static final KeyConvertor keyConvertor = new KeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();

    /**
     * Execute this step with given context
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.fromMap(context);

        // Intiate the step sequence
        logStart(stepLogger);

        // Get data from status
        String activationId = JsonUtil.stringValue(model.getResultStatusObject(), "activationId");
        long counter = JsonUtil.longValue(model.getResultStatusObject(), ("counter"));
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signaturePossessionKey"));
        byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureBiometryKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureKnowledgeKeyEncrypted"));

        // Get password to unlock the knowledge factor key
        char[] password = VerifySignatureUtil.getKnowledgeKeyPassword(model);

        // Get the signature keys
        SecretKey signaturePossessionKey = keyConvertor.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signatureBiometryKey = keyConvertor.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

        // Generate nonce
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);

        // Construct the signature base string data part based on HTTP method (GET requires different code).
        byte[] dataFileBytes = VerifySignatureUtil.extractRequestDataBytes(model, stepLogger);

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(model.getHttpMethod().toUpperCase(), model.getResourceId(), nonceBytes, dataFileBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion());
        String signatureValue = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData, signatureFormat);
        final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), signatureValue, model.getSignatureType().toString(), BaseEncoding.base64().encode(nonceBytes), model.getVersion());
        String httpAuthorizationHeader = header.buildHttpHeader();

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
            lowLevelData.put("applicationSecret", model.getApplicationSecret());

            stepLogger.writeItem(
                    "signature-verify-prepare-request",
                    "Signature Calculation Parameters",
                    "Low level cryptographic inputs required to compute signature - mainly a signature base string and a counter value.",
                    "OK",
                    lowLevelData
            );
        }

        // Increment the counter
        CounterUtil.incrementCounter(model);

        // Store the activation status (updated counter)
        String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
        try (FileWriter file = new FileWriter(model.getStatusFileName())) {
            file.write(formatted);
        }

        // Call the server with activation data
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, httpAuthorizationHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall("signature-verify-request-sent", model.getUriString(), model.getHttpMethod().toUpperCase(), new String(dataFileBytes, StandardCharsets.UTF_8), headers);
            }

            if (!model.isDryRun()) {
                final boolean success = executeRequest(model.getHttpMethod().toUpperCase(), headers, model.getUriString(), dataFileBytes, stepLogger);
                if (success) {
                    return model.getResultStatusObject();
                } else {
                    return null;
                }
            } else {
                logSignatureComputed(stepLogger);
                return model.getResultStatusObject();
            }
        } catch (Exception exception) {
            logException("signature-verify-error-generic", exception, stepLogger);
            return null;
        }
    }

    /**
     * Logs the start of the method execution.
     * @param stepLogger Logger instance.
     */
    private void logStart(StepLogger stepLogger) {
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "signature-verify-start",
                    "Signature Validation Started",
                    null,
                    "OK",
                    null
            );
        }
    }

    /**
     * Log exception.
     * @param id ID to be used for the exception log.
     * @param exception Exception to be logged.
     * @param stepLogger Logger instance.
     */
    private void logException(String id, Exception exception, StepLogger stepLogger) {
        if (stepLogger != null) {
            stepLogger.writeError(id, exception);
            stepLogger.writeDoneFailed("signature-verify-failed");
        }
    }

    /**
     * Log that the signature was successfully completed.
     * @param stepLogger Logger instance.
     */
    private void logSignatureComputed(StepLogger stepLogger) {
        if (stepLogger != null) {
            // Print the results
            stepLogger.writeItem(
                    "signature-verify-signature-computed",
                    "Signature computed",
                    "Activation signature header was computed successfully",
                    "OK",
                    null

            );
            stepLogger.writeDoneOK("signature-verify-success");
        }
    }

    /**
     * Execute request for the signature validation.
     * @param method HTTP method.
     * @param headers HTTP headers.
     * @param uri Full URI to be used for signature validation.
     * @param data HTTP request body.
     * @param stepLogger Logger instance.
     * @return True in case the request is successful, false otherwise.
     * @throws JsonProcessingException In case parsing the response to JSON format fails.
     */
    private boolean executeRequest(String method, Map<String, String> headers, String uri, byte[] data, StepLogger stepLogger) throws JsonProcessingException {
        ClientResponse response;
        WebClient webClient = WebClientFactory.getWebClient();
        if ("GET".equals(method)) {
            response = webClient
                    .get()
                    .uri(uri)
                    .headers(h -> {
                        h.addAll(MapUtil.toMultiValueMap(headers));
                    })
                    .exchange()
                    .block();
        } else {
            response = webClient
                    .post()
                    .uri(uri)
                    .headers(h -> {
                        h.addAll(MapUtil.toMultiValueMap(headers));
                    })
                    .body(BodyInserters.fromValue(data))
                    .exchange()
                    .block();
        }
        if (response == null) {
            if (stepLogger != null) {
                stepLogger.writeError("signature-verify-error-generic", "Response is missing");
                stepLogger.writeDoneFailed("signature-verify-failed");
            }
            return false;
        }
        if (response.statusCode().isError()) {
            if (stepLogger != null) {
                stepLogger.writeServerCallError("signature-verify-error-server-call", response.rawStatusCode(), response.bodyToMono(String.class).block(), HttpUtil.flattenHttpHeaders(response.headers().asHttpHeaders()));
                stepLogger.writeDoneFailed("signature-verify-failed");
            }
            return false;
        }

        ParameterizedTypeReference<ObjectResponse<Map<String, Object>>> typeReference = new ParameterizedTypeReference<ObjectResponse<Map<String, Object>>>() {};
        ResponseEntity<ObjectResponse<Map<String, Object>>> responseEntity = Objects.requireNonNull(response.toEntity(typeReference).block());
        ObjectResponse<Map<String, Object>> responseWrapper = Objects.requireNonNull(responseEntity.getBody());


        if (stepLogger != null) {
            stepLogger.writeServerCallOK("signature-verify-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(response.headers().asHttpHeaders()));

            // Print the results
            stepLogger.writeItem(
                    "signature-verify-signature-verified",
                    "Signature verified",
                    "Activation signature was verified successfully",
                    "OK",
                    null

            );

            stepLogger.writeDoneOK("signature-verify-success");
        }
        return true;
    }

}
