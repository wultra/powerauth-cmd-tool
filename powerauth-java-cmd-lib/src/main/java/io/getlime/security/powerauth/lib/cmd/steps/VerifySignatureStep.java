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
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;
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
 * Helper class with signature verification logics.
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
        JSONObject resultStatusObject = (JSONObject) context.get("STATUS_OBJECT");
        String uri = (String) context.get("URI_STRING");
        String statusFileName = (String) context.get("STATUS_FILENAME");
        String applicationKey = (String) context.get("APPLICATION_KEY");
        String applicationSecret = (String) context.get("APPLICATION_SECRET");
        String httpMethod = ((String) context.get("HTTP_METHOD")).toUpperCase();
        String endpoint = (String) context.get("ENDPOINT");
        String signatureType = (String) context.get("SIGNATURE_TYPE");
        String dataFileName = (String) context.get("DATA_FILE_NAME");
        String passwordProvided = (String) context.get("PASSWORD");

        stepLogger.writeItem(
                "Signature Validation Started",
                null,
                "OK",
                null
        );

        // Get data from status
        String activationId = (String) resultStatusObject.get("activationId");
        long counter = (long) resultStatusObject.get("counter");
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signaturePossessionKey"));
        byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureBiometryKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) resultStatusObject.get("signatureKnowledgeKeyEncrypted"));

        // Ask for the password to unlock knowledge factor key
        char[] password;
        if (passwordProvided == null) {
            Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
        } else {
            password = passwordProvided.toCharArray();
        }

        // Get the signature keys
        SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signatureBiometryKey = keyConversion.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        // Construct the signature base string data part based on HTTP method (GET requires different code).
        byte[] dataFileBytes;
        if ("GET".equals(httpMethod.toUpperCase())) {
            String query = new URI(uri).getRawQuery();
            String canonizedQuery = PowerAuthRequestCanonizationUtils.canonizeGetParameters(query);
            if (canonizedQuery != null) {
                dataFileBytes = canonizedQuery.getBytes("UTF-8");
            } else {
                dataFileBytes = new byte[0];
                stepLogger.writeItem(
                        "Empty data",
                        "No GET query parameters found in provided URL, signature will contain no data",
                        "WARNING",
                        null
                );
            }
        } else {
            // Read data input file
            if (dataFileName != null && Files.exists(Paths.get(dataFileName))) {
                dataFileBytes = Files.readAllBytes(Paths.get(dataFileName));
            } else {
                dataFileBytes = new byte[0];
                stepLogger.writeItem(
                        "Empty data",
                        "Data file was not found, signature will contain no data",
                        "WARNING",
                        null
                );
            }
        }

        // Compute the current PowerAuth 2.0 signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(httpMethod.toUpperCase(), endpoint, pa_nonce, dataFileBytes) + "&" + applicationSecret;
        String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), keyFactory.keysForSignatureType(signatureType, signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), counter);
        String httpAuhtorizationHeader = PowerAuthHttpHeader.getPowerAuthSignatureHTTPHeader(activationId, applicationKey, BaseEncoding.base64().encode(pa_nonce), PowerAuthSignatureTypes.getEnumFromString(signatureType).toString(), pa_signature, "2.0");

        // Increment the counter
        counter += 1;
        resultStatusObject.put("counter", counter);

        // Store the activation status (updated counter)
        String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(resultStatusObject);
        try (FileWriter file = new FileWriter(statusFileName)) {
            file.write(formatted);
        }

        // Call the server with activation data
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthHttpHeader.HEADER_NAME, httpAuhtorizationHeader);

            stepLogger.writeServerCall(uri, httpMethod.toUpperCase(), new String(dataFileBytes, "UTF-8"), headers);

            HttpResponse response;
            if ("GET".equals(httpMethod)) {
                response = Unirest.get(uri)
                        .headers(headers)
                        .asString();
            } else {
                response = Unirest.post(uri)
                        .headers(headers)
                        .body(dataFileBytes)
                        .asString();
            }

            TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {};
            Map<String, Object> responseWrapper = RestClientConfiguration
                    .defaultMapper()
                    .readValue(response.getRawBody(), typeReference);

            if (response.getStatus() == 200) {

                stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));

                // Print the results
                stepLogger.writeItem(
                        "Signature verified",
                        "Activation signature was verified successfully",
                        "OK",
                        null

                );

                stepLogger.writeDoneOK();
                return resultStatusObject;
            } else {
                stepLogger.writeServerCallError(response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                stepLogger.writeDoneFailed();
                return null;
            }
        } catch (UnirestException exception) {
            stepLogger.writeServerCallConnectionError(exception);
            stepLogger.writeDoneFailed();
            return null;
        } catch (Exception exception) {
            stepLogger.writeError(exception);
            stepLogger.writeDoneFailed();
            return null;
        }
    }

}
