/*
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
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.VaultUnlockResponsePayload;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with vault unlock logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class VaultUnlockStep implements BaseStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();
    private static final EciesFactory eciesFactory = new EciesFactory();

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
                    "Vault Unlock Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/v3/vault/unlock";

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
        SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signatureBiometryKey = keyConversion.convertBytesToSharedSecretKey(signatureBiometryKeyBytes);

        // Get the transport key
        SecretKey transportMasterKey = keyConversion.convertBytesToSharedSecretKey(transportMasterKeyBytes);

        // Generate nonce
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);

        // Get the vault unlocked reason
        String reason = model.getReason();

        // Prepare vault unlock request payload
        VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason(reason);

        // Prepare ECIES encryptor and encrypt request data with sharedInfo1 = /pa/vault/unlock
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConversion.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, EciesSharedInfo1.VAULT_UNLOCK);

        // Encrypt the request
        final byte[] requestBytesPayload = RestClientConfiguration.defaultMapper().writeValueAsBytes(requestPayload);
        final EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest(requestBytesPayload);

        // Prepare encrypted request object
        EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey()));
        eciesRequest.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData()));
        eciesRequest.setMac(BaseEncoding.base64().encode(eciesCryptogram.getMac()));

        final byte[] requestBytes = mapper.writeValueAsBytes(eciesRequest);

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", nonceBytes, requestBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion());
        String signatureValue = signature.signatureForData(signatureBaseString.getBytes("UTF-8"), keyFactory.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData, signatureFormat);
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
                stepLogger.writeServerCall(uri, "POST", eciesRequest, headers);
            }

            HttpResponse response = Unirest.post(uri)
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

                // Read encrypted response and decrypt it
                byte[] mac = BaseEncoding.base64().decode(encryptedResponse.getMac());
                byte[] encryptedData = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
                EciesCryptogram responseCryptogram = new EciesCryptogram(mac, encryptedData);
                byte[] decryptedData = eciesEncryptor.decryptResponse(responseCryptogram);

                // Read vault unlock response payload and extract the vault encryption key
                VaultUnlockResponsePayload responsePayload = mapper.readValue(decryptedData, VaultUnlockResponsePayload.class);

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Decrypted Response",
                            "Following vault unlock data were decrypted",
                            "OK",
                            responsePayload
                    );
                }

                byte[] encryptedVaultEncryptionKey = BaseEncoding.base64().decode(responsePayload.getEncryptedVaultEncryptionKey());

                PowerAuthClientVault vault = new PowerAuthClientVault();
                SecretKey vaultEncryptionKey = vault.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey);
                PrivateKey devicePrivateKey = vault.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);

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
