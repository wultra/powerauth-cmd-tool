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
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.request.v2.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.VaultUnlockResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with vault unlock logics.
 *
 * @author Petr Dvorak
 *
 */
public class VaultUnlockStep implements BaseStep {

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
    public JSONObject execute(JsonStepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        VaultUnlockStepModel model = new VaultUnlockStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Vault Unlock Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/vault/unlock";

        // Get data from status
        String activationId = (String) model.getResultStatusObject().get("activationId");
        long counter = (long) model.getResultStatusObject().get("counter");
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureBiometryKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));
        byte[] transportMasterKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("transportMasterKey"));
        byte[] encryptedDevicePrivateKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("encryptedDevicePrivateKey"));
        byte[] serverPublicKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("serverPublicKey"));

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

        // Get the transport key
        SecretKey transportMasterKey = keyConversion.convertBytesToSharedSecretKey(transportMasterKeyBytes);

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        // Get the vault unlocked reason
        String reason = model.getReason();

        // Prepare vault unlock request
        VaultUnlockRequest vaultUnlockRequest = new VaultUnlockRequest();
        vaultUnlockRequest.setReason(reason);
        ObjectRequest<VaultUnlockRequest> request = new ObjectRequest<>(vaultUnlockRequest);
        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        // Compute the current PowerAuth 2.0 signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("post", "/pa/vault/unlock", pa_nonce, requestBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        String pa_signature = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), keyFactory.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData);
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), pa_signature, model.getSignatureType().toString(), BaseEncoding.base64().encode(pa_nonce), model.getVersion());
        String httpAuthorizationHeader = header.buildHttpHeader();

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
                stepLogger.writeServerCall(uri, "POST", request.getRequestObject(), headers);
            }

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(requestBytes)
                    .asString();

            if (response.getStatus() == 200) {

                TypeReference<ObjectResponse<VaultUnlockResponse>> typeReference = new TypeReference<ObjectResponse<VaultUnlockResponse>>() {};
                ObjectResponse<VaultUnlockResponse> responseWrapper = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getRawBody(), typeReference);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                VaultUnlockResponse responseObject = responseWrapper.getResponseObject();
                byte[] encryptedVaultEncryptionKey = BaseEncoding.base64().decode(responseObject.getEncryptedVaultEncryptionKey());

                PowerAuthClientVault vault = new PowerAuthClientVault();
                SecretKey vaultEncryptionKey = vault.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey, counter);
                PrivateKey devicePrivateKey = vault.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);
                PublicKey serverPublicKey = keyConversion.convertBytesToPublicKey(serverPublicKeyBytes);

                // Increment the counter
                CounterUtil.incrementCounter(model);

                // Store the activation status (updated counter)
                formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(formatted);
                }

                SecretKey masterSecretKey = keyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey transportKeyDeduced = keyFactory.generateServerTransportKey(masterSecretKey);
                boolean equal = transportKeyDeduced.equals(transportMasterKey);

                // Print the results
                Map<String, Object> objectMap = new HashMap<>();
                objectMap.put("activationId", activationId);
                objectMap.put("encryptedVaultEncryptionKey", BaseEncoding.base64().encode(encryptedVaultEncryptionKey));
                objectMap.put("transportMasterKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(transportMasterKey)));
                objectMap.put("vaultEncryptionKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(vaultEncryptionKey)));
                objectMap.put("devicePrivateKey", BaseEncoding.base64().encode(keyConversion.convertPrivateKeyToBytes(devicePrivateKey)));
                objectMap.put("privateKeyDecryptionSuccessful", (equal ? "true" : "false"));

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Vault Unlocked",
                            "Secure vault was successfully unlocked",
                            "OK",
                            objectMap
                    );
                    stepLogger.writeDoneOK();
                }
                return model.getResultStatusObject();
            } else {

                // Increment the counter
                CounterUtil.incrementCounter(model);

                // Store the activation status (updated counter)
                formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(formatted);
                }

                if (stepLogger != null) {
                    stepLogger.writeServerCallError(response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                    stepLogger.writeDoneFailed();
                }
                return null;
            }


        } catch (UnirestException exception) {

            // Increment the counter, second time for vault unlock
            CounterUtil.incrementCounter(model);

            // Store the activation status (updated counter)
            formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
            try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                file.write(formatted);
            }

            if (stepLogger != null) {
                stepLogger.writeServerCallConnectionError(exception);
                stepLogger.writeDoneFailed();
            }
            return null;
        } catch (Exception exception) {

            // Increment the counter, second time for vault unlock
            CounterUtil.incrementCounter(model);

            // Store the activation status (updated counter)
            formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
            try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                file.write(formatted);
            }

            if (stepLogger != null) {
                stepLogger.writeError(exception);
                stepLogger.writeDoneFailed();
            }
            return null;
        }
    }

}
