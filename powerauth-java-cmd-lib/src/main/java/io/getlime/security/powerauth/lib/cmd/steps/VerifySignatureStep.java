/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with signature verification logic.
 *
 * @author Petr Dvorak
 *
 */
public class VerifySignatureStep implements BaseStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final ObjectMapper mapper = new ObjectMapper();

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
                    "Signature Validation Started",
                    null,
                    "OK",
                    null
            );
        }

        // Get data from status
        String activationId = (String) model.getResultStatusObject().get("activationId");
        long counter = (long) model.getResultStatusObject().get("counter");
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureBiometryKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Ask for the password to unlock knowledge factor key
        char[] password;
        if (model.getPassword() == null) {
            Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
        } else {
            password = model.getPassword().toCharArray();
        }

        // Get the signature keys
        SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signatureBiometryKey = keyConversion.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        // Construct the signature base string data part based on HTTP method (GET requires different code).
        byte[] dataFileBytes;
        if ("GET".equals(model.getHttpMethod().toUpperCase())) {
            String query = new URI(model.getUriString()).getRawQuery();
            String canonizedQuery = PowerAuthRequestCanonizationUtils.canonizeGetParameters(query);
            if (canonizedQuery != null) {
                dataFileBytes = canonizedQuery.getBytes("UTF-8");
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Normalized GET data",
                            "GET query data were normalized into the canonical string.",
                            "OK",
                            canonizedQuery
                    );
                }
            } else {
                dataFileBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Empty data",
                            "No GET query parameters found in provided URL, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        } else {
            // Read data input file
            if (model.getDataFileName() != null && Files.exists(Paths.get(model.getDataFileName()))) {
                dataFileBytes = Files.readAllBytes(Paths.get(model.getDataFileName()));
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Request payload",
                            "Data from the request payload file, used as the POST / DELETE / ... method body, encoded as Base64.",
                            "OK",
                            BaseEncoding.base64().encode(dataFileBytes)
                    );
                }
            } else {
                dataFileBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Empty data",
                            "Data file was not found, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        }

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(model.getHttpMethod().toUpperCase(), model.getResourceId(), pa_nonce, dataFileBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), keyFactory.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData);
        final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), pa_signature, model.getSignatureType().toString(), BaseEncoding.base64().encode(pa_nonce), model.getVersion());
        String httpAuthorizationHeader = header.buildHttpHeader();



        if (stepLogger != null) {

            Map<String, String> lowLevelData = new HashMap<>();
            lowLevelData.put("counter", String.valueOf(counter));
            int version = (int) model.getResultStatusObject().get("version");
            if (version == 3) {
                lowLevelData.put("ctrData", BaseEncoding.base64().encode(ctrData));
            }
            lowLevelData.put("signatureBaseString", signatureBaseString);
            lowLevelData.put("resourceId", model.getResourceId());
            lowLevelData.put("nonce", BaseEncoding.base64().encode(pa_nonce));
            lowLevelData.put("applicationSecret", model.getApplicationSecret());

            stepLogger.writeItem(
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
                stepLogger.writeServerCall(model.getUriString(), model.getHttpMethod().toUpperCase(), new String(dataFileBytes, "UTF-8"), headers);
            }

            HttpResponse response;
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
                TypeReference<Response> typeReference = new TypeReference<Response>() {};
                Response responseWrapper = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getRawBody(), typeReference);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));

                    // Print the results
                    stepLogger.writeItem(
                            "Signature verified",
                            "Activation signature was verified successfully",
                            "OK",
                            null

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
