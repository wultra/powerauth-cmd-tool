/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.token.ClientTokenGenerator;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.BasicEciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.entity.TokenResponsePayload;
import io.getlime.security.powerauth.rest.api.model.request.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.TokenCreateResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with token creation logic.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class CreateTokenStep implements BaseStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final ClientTokenGenerator tokenGenerator = new ClientTokenGenerator();
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Execute this step with given context
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    @Override
    public JSONObject execute(JsonStepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        CreateTokenStepModel model = new CreateTokenStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Token Create Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/token/create";

        // Get data from status
        String activationId = (String) model.getResultStatusObject().get("activationId");
        long counter = (long) model.getResultStatusObject().get("counter");
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
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

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        BasicEciesEncryptor encryptor = new BasicEciesEncryptor((ECPublicKey) model.getMasterPublicKey());
        final PublicKey ephemeralPublicKey = encryptor.getEphemeralPublicKey();
        final byte[] ephemeralPublicKeyBytes = keyConversion.convertPublicKeyToBytes(ephemeralPublicKey);
        final EciesPayload eciesPayload = encryptor.encrypt(new byte[0], ephemeralPublicKeyBytes);

        // Prepare encryption request
        TokenCreateRequest requestObject = new TokenCreateRequest();
        String ephemeralPublicKeyBase64 = BaseEncoding.base64().encode(ephemeralPublicKeyBytes);
        requestObject.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        ObjectRequest<TokenCreateRequest> request = new ObjectRequest<>(requestObject);

        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);


        // Compute the current PowerAuth 2.0 signature for possession
        // and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/token/create", pa_nonce, requestBytes) + "&" + model.getApplicationSecret();
        String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), counter);
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), pa_signature, model.getSignatureType().toString(), BaseEncoding.base64().encode(pa_nonce), "2.0");
        String httpAuhtorizationHeader = header.buildHttpHeader();

        // Increment the counter
        counter += 1;
        model.getResultStatusObject().put("counter", counter);

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
            headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, httpAuhtorizationHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall(uri, "POST", requestObject, headers);
            }

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(requestBytes)
                    .asString();

            TypeReference<ObjectResponse<TokenCreateResponse>> typeReference = new TypeReference<ObjectResponse<TokenCreateResponse>>() {};
            ObjectResponse<TokenCreateResponse> responseWrapper = RestClientConfiguration
                    .defaultMapper()
                    .readValue(response.getRawBody(), typeReference);

            if (response.getStatus() == 200) {
                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                final TokenCreateResponse responseObject = responseWrapper.getResponseObject();

                byte[] mac = BaseEncoding.base64().decode(responseObject.getMac());
                byte[] encryptedBody = BaseEncoding.base64().decode(responseObject.getEncryptedData());
                EciesPayload eciesResponsePayload = new EciesPayload(eciesPayload.getEphemeralPublicKey(), mac, encryptedBody);

                final byte[] decryptedBytes = encryptor.decrypt(eciesResponsePayload);

                final TokenResponsePayload tokenResponsePayload = RestClientConfiguration.defaultMapper().readValue(decryptedBytes, TokenResponsePayload.class);

                Map<String, Object> objectMap = new HashMap<>();
                objectMap.put("tokenId", tokenResponsePayload.getTokenId());
                objectMap.put("tokenSecret", tokenResponsePayload.getTokenSecret());
                objectMap.put("expires", tokenResponsePayload.getExpires());

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Token successfully obtained",
                            "Token was successfully generated and decrypted",
                            "OK",
                            objectMap

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
