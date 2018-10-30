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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class with prepare activation logic.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PrepareActivationStep implements BaseStep {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientVault vault = new PowerAuthClientVault();
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
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Activation Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/activation/create";

        // Fetch and parse the activation code
        Pattern p = Pattern.compile("^[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}(#.*)?$");
        Matcher m = p.matcher(model.getActivationCode());
        if (!m.find()) {
            if (stepLogger != null) {
                stepLogger.writeError("Activation failed", "Activation code has invalid format");
                stepLogger.writeDoneFailed();
                return null;
            }
        }
        String activationIdShort = model.getActivationCode().substring(0, 11);
        String activationOTP = model.getActivationCode().substring(12, 23);


        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationCode", model.getActivationCode());
        objectMap.put("activationIdShort", activationIdShort);
        objectMap.put("activationOtp", activationOTP);
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Activation code",
                    "Parsing activation code to short activation ID and activation OTP",
                    "OK",
                    objectMap
            );
        }

        // Generate device key pair and encrypt the device public key
        KeyPair clientEphemeralKeyPair = keyGenerator.generateKeyPair();

        // Generate device key pair and encrypt the device public key
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] nonceDeviceBytes = activation.generateActivationNonce();
        byte[] cDevicePublicKeyBytes = activation.encryptDevicePublicKey(
                deviceKeyPair.getPublic(),
                clientEphemeralKeyPair.getPrivate(),
                model.getMasterPublicKey(),
                activationOTP,
                activationIdShort,
                nonceDeviceBytes
        );
        byte[] signature = activation.computeApplicationSignature(
                activationIdShort,
                nonceDeviceBytes,
                cDevicePublicKeyBytes,
                BaseEncoding.base64().decode(model.getApplicationKey()),
                BaseEncoding.base64().decode(model.getApplicationSecret())
        );
        byte[] ephemeralPublicKeyBytes = keyConversion.convertPublicKeyToBytes(clientEphemeralKeyPair.getPublic());

        // Prepare the server request
        ActivationCreateRequest requestObject = new ActivationCreateRequest();
        requestObject.setActivationIdShort(activationIdShort);
        requestObject.setApplicationKey(model.getApplicationKey());
        requestObject.setActivationName(model.getActivationName());
        requestObject.setActivationNonce(BaseEncoding.base64().encode(nonceDeviceBytes));
        requestObject.setEphemeralPublicKey(BaseEncoding.base64().encode(ephemeralPublicKeyBytes));
        requestObject.setEncryptedDevicePublicKey(BaseEncoding.base64().encode(cDevicePublicKeyBytes));
        requestObject.setApplicationSignature(BaseEncoding.base64().encode(signature));
        ObjectRequest<ActivationCreateRequest> body = new ObjectRequest<>();
        body.setRequestObject(requestObject);

        // Call the server with activation data
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall(uri, "POST", requestObject, headers);
            }

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(body)
                    .asString();

            if (response.getStatus() == 200) {
                TypeReference<ObjectResponse<ActivationCreateResponse>> typeReference = new TypeReference<ObjectResponse<ActivationCreateResponse>>() {};
                ObjectResponse<ActivationCreateResponse> responseWrapper = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getRawBody(), typeReference);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                // Process the server response
                ActivationCreateResponse responseObject = responseWrapper.getResponseObject();
                String activationId = responseObject.getActivationId();
                byte[] nonceServerBytes = BaseEncoding.base64().decode(responseObject.getActivationNonce());
                byte[] cServerPubKeyBytes = BaseEncoding.base64().decode(responseObject.getEncryptedServerPublicKey());
                byte[] cServerPubKeySignatureBytes = BaseEncoding.base64().decode(responseObject.getEncryptedServerPublicKeySignature());
                byte[] ephemeralKeyBytes = BaseEncoding.base64().decode(responseObject.getEphemeralPublicKey());
                PublicKey ephemeralPublicKey = keyConversion.convertBytesToPublicKey(ephemeralKeyBytes);

                // Verify that the server public key signature is valid
                boolean isDataSignatureValid = activation.verifyServerDataSignature(activationId, cServerPubKeyBytes, cServerPubKeySignatureBytes, model.getMasterPublicKey());

                if (isDataSignatureValid) {

                    // Decrypt the server public key
                    PublicKey serverPublicKey = activation.decryptServerPublicKey(cServerPubKeyBytes, deviceKeyPair.getPrivate(), ephemeralPublicKey, activationOTP, activationIdShort, nonceServerBytes);

                    // Compute master secret key
                    SecretKey masterSecretKey = keyFactory.generateClientMasterSecretKey(deviceKeyPair.getPrivate(), serverPublicKey);

                    // Derive PowerAuth keys from master secret key
                    SecretKey signaturePossessionSecretKey = keyFactory.generateClientSignaturePossessionKey(masterSecretKey);
                    SecretKey signatureKnoweldgeSecretKey = keyFactory.generateClientSignatureKnowledgeKey(masterSecretKey);
                    SecretKey signatureBiometrySecretKey = keyFactory.generateClientSignatureBiometryKey(masterSecretKey);
                    SecretKey transportMasterKey = keyFactory.generateServerTransportKey(masterSecretKey);
                    // DO NOT EVER STORE ...
                    SecretKey vaultUnlockMasterKey = keyFactory.generateServerEncryptedVaultKey(masterSecretKey);

                    // Encrypt the original device private key using the vault unlock key
                    byte[] encryptedDevicePrivateKey = vault.encryptDevicePrivateKey(deviceKeyPair.getPrivate(), vaultUnlockMasterKey);

                    char[] password;
                    if (model.getPassword() == null) {
                        Console console = System.console();
                        password = console.readPassword("Select a password to encrypt the knowledge related key: ");
                    } else {
                        password = model.getPassword().toCharArray();
                    }

                    byte[] salt = keyGenerator.generateRandomBytes(16);
                    byte[] cSignatureKnowledgeSecretKey = EncryptedStorageUtil.storeSignatureKnowledgeKey(password, signatureKnoweldgeSecretKey, salt, keyGenerator);

                    // Prepare the status object to be stored
                    model.getResultStatusObject().put("activationId", activationId);
                    model.getResultStatusObject().put("serverPublicKey", BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(serverPublicKey)));
                    model.getResultStatusObject().put("encryptedDevicePrivateKey", BaseEncoding.base64().encode(encryptedDevicePrivateKey));
                    model.getResultStatusObject().put("signaturePossessionKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signaturePossessionSecretKey)));
                    model.getResultStatusObject().put("signatureKnowledgeKeyEncrypted", BaseEncoding.base64().encode(cSignatureKnowledgeSecretKey));
                    model.getResultStatusObject().put("signatureKnowledgeKeySalt", BaseEncoding.base64().encode(salt));
                    model.getResultStatusObject().put("signatureBiometryKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signatureBiometrySecretKey)));
                    model.getResultStatusObject().put("transportMasterKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(transportMasterKey)));
                    model.getResultStatusObject().put("counter", 0L);
                    model.getResultStatusObject().put("ctrData", null);
                    model.getResultStatusObject().put("version", 2);

                    // Store the resulting status
                    String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                    try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                        file.write(formatted);
                    }

                    objectMap = new HashMap<>();
                    objectMap.put("activationId", activationId);
                    objectMap.put("activationStatusFile", model.getStatusFileName());
                    objectMap.put("activationStatusFileContent", model.getResultStatusObject());
                    objectMap.put("deviceKeyFingerprint", activation.computeDevicePublicKeyFingerprint(deviceKeyPair.getPublic()));
                    if (stepLogger != null) {
                        stepLogger.writeItem(
                                "Activation Done",
                                "Public key exchange was successfully completed, commit the activation on server",
                                "OK",
                                objectMap
                        );
                        stepLogger.writeDoneOK();
                    }

                    return model.getResultStatusObject();

                } else {
                    if (stepLogger != null) {
                        String message = "Activation data signature does not match. Either someone tried to spoof your connection, or your device master key is invalid.";
                        stepLogger.writeError(message);
                        stepLogger.writeDoneFailed();
                    }
                    return null;
                }
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
