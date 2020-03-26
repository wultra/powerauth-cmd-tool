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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
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
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

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

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "signature-verify-start",
                    "Signature Validation Started",
                    null,
                    "OK",
                    null
            );
        }

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

                HttpResponse<String> response;
                if ("GET".equals(model.getHttpMethod().toUpperCase())) {
                    response = Unirest.get(model.getUriString())
                            .headers(headers)
                            .asString();
                } else {
                    response = Unirest.post(model.getUriString())
                            .headers(headers)
                            .body(dataFileBytes)
                            .asString();
                }

                if (response.getStatus() == 200) {
                    TypeReference<ObjectResponse<Map<String, Object>>> typeReference = new TypeReference<ObjectResponse<Map<String, Object>>>() {
                    };
                    Response responseWrapper = RestClientConfiguration
                            .defaultMapper()
                            .readValue(response.getBody(), typeReference);

                    if (stepLogger != null) {
                        stepLogger.writeServerCallOK("signature-verify-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));

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
                    return model.getResultStatusObject();
                } else {
                    if (stepLogger != null) {
                        stepLogger.writeServerCallError("signature-verify-error-server-call", response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                        stepLogger.writeDoneFailed("signature-verify-failed");
                    }
                    return null;
                }

            } else {
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
                return model.getResultStatusObject();
            }
        } catch (UnirestException exception) {
            if (stepLogger != null) {
                stepLogger.writeServerCallConnectionError("signature-verify-error-connection", exception);
                stepLogger.writeDoneFailed("signature-verify-failed");
            }
            return null;
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError("signature-verify-error-generic", exception);
                stepLogger.writeDoneFailed("signature-verify-failed");
            }
            return null;
        }
    }

}
