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
package io.getlime.security.powerauth.lib.cmd.steps.v2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.v2.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.VaultUnlockResponse;
import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Helper class with vault unlock logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak
 *
 */
public class VaultUnlockStep implements BaseStep {

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
        VaultUnlockStepModel model = new VaultUnlockStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "vault-unlock-start",
                    "Vault Unlock Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/vault/unlock";

        // Get data from status
        String activationId = JsonUtil.stringValue(model.getResultStatusObject(), "activationId");
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signaturePossessionKey"));
        byte[] signatureBiometryKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureBiometryKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signatureKnowledgeKeyEncrypted"));
        byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "transportMasterKey"));
        byte[] encryptedDevicePrivateKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "encryptedDevicePrivateKey"));
        byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "serverPublicKey"));

        // Ask for the password to unlock knowledge factor key
        char[] password;
        if (model.getPassword() == null) {
            Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
        } else {
            password = model.getPassword().toCharArray();
        }

        // Get the signature keys
        SecretKey signaturePossessionKey = keyConvertor.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signatureBiometryKey = keyConvertor.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

        // Get the transport key
        SecretKey transportMasterKey = keyConvertor.convertBytesToSharedSecretKey(transportMasterKeyBytes);

        // Generate nonce
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);

        // Get the vault unlocked reason
        String reason = model.getReason();

        // Prepare vault unlock request
        VaultUnlockRequest vaultUnlockRequest = new VaultUnlockRequest();
        vaultUnlockRequest.setReason(reason);
        ObjectRequest<VaultUnlockRequest> request = new ObjectRequest<>(vaultUnlockRequest);
        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", nonceBytes, requestBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion());
        String signatureValue = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData, signatureFormat);
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), signatureValue, model.getSignatureType().toString(), BaseEncoding.base64().encode(nonceBytes), model.getVersion());
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
                stepLogger.writeServerCall("vault-unlock-request-sent", uri, "POST", request.getRequestObject(), headers);
            }

            ResponseEntity<ObjectResponse<VaultUnlockResponse>> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            ParameterizedTypeReference<ObjectResponse<VaultUnlockResponse>> typeReference = new ParameterizedTypeReference<ObjectResponse<VaultUnlockResponse>>() {};
            try {
                responseEntity = restClient.post(uri, requestBytes, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                // Increment the counter
                CounterUtil.incrementCounter(model);

                // Store the activation status (updated counter)
                formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(formatted);
                }

                if (stepLogger != null) {
                    stepLogger.writeServerCallError("vault-unlock-error-server-call",  ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                    stepLogger.writeDoneFailed("vault-unlock-failed");
                }
                return null;
            }

            ObjectResponse<VaultUnlockResponse> responseWrapper = Objects.requireNonNull(responseEntity.getBody());

            if (stepLogger != null) {
                stepLogger.writeServerCallOK("vault-unlock-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));
            }

            VaultUnlockResponse responseObject = responseWrapper.getResponseObject();
            byte[] encryptedVaultEncryptionKey = BaseEncoding.base64().decode(responseObject.getEncryptedVaultEncryptionKey());

            PowerAuthClientVault vault = new PowerAuthClientVault();
            ctrData = CounterUtil.getCtrData(model, stepLogger);
            SecretKey vaultEncryptionKey = vault.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey, ctrData);
            PrivateKey devicePrivateKey = vault.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);
            PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);

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
            objectMap.put("transportMasterKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(transportMasterKey)));
            objectMap.put("vaultEncryptionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(vaultEncryptionKey)));
            objectMap.put("devicePrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
            objectMap.put("privateKeyDecryptionSuccessful", (equal ? "true" : "false"));

            if (stepLogger != null) {
                stepLogger.writeItem(
                        "vault-unlock-finished",
                        "Vault Unlocked",
                        "Secure vault was successfully unlocked",
                        "OK",
                        objectMap
                );
                stepLogger.writeDoneOK("vault-unlock-success");
            }
            return model.getResultStatusObject();


        } catch (Exception exception) {

            // Increment the counter, second time for vault unlock
            CounterUtil.incrementCounter(model);

            // Store the activation status (updated counter)
            formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
            try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                file.write(formatted);
            }

            if (stepLogger != null) {
                stepLogger.writeError("vault-unlock-error-generic", exception);
                stepLogger.writeDoneFailed("vault-unlock-failed");
            }
            return null;
        }
    }

}
