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
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class with prepare activation logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component(value = "prepareActivationStepV2")
public class PrepareActivationStep extends AbstractBaseStepV2 {

    public static final ParameterizedTypeReference<ObjectResponse<ActivationCreateResponse>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<ObjectResponse<ActivationCreateResponse>>() {
            };

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final KeyConvertor keyConversion = new KeyConvertor();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientVault vault = new PowerAuthClientVault();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();

    @Autowired
    public PrepareActivationStep(StepLogger stepLogger) {
        super(PowerAuthStep.ACTIVATION_CREATE, PowerAuthVersion.VERSION_2, stepLogger);
    }

    /**
     * Constructor for backward compatibility
     */
    public PrepareActivationStep() {
        this(DEFAULT_STEP_LOGGER);
    }

    /**
     * Execute this step with given context
     *
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(Map<String, Object> context) throws Exception {

        // Read properties from "context"
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.fromMap(context);

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/activation/create";

        // Fetch and parse the activation code
        Pattern p = Pattern.compile("^[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}(#.*)?$");
        Matcher m = p.matcher(model.getActivationCode());
        if (!m.find()) {
            if (stepLogger != null) {
                stepLogger.writeError("activation-create-error-activation-code", "Activation failed", "Activation code has invalid format");
                stepLogger.writeDoneFailed("activation-create-failed");
                return null;
            }
        }
        String activationIdShort = model.getActivationCode().substring(0, 11);
        String activationOTP = model.getActivationCode().substring(12, 23);


        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationCode", model.getActivationCode());
        objectMap.put("activationIdShort", activationIdShort);
        objectMap.put("activationOtp", activationOTP);
        stepLogger.writeItem(
                "activation-create-activation-code-parsed",
                "Activation code",
                "Parsing activation code to short activation ID and activation OTP",
                "OK",
                objectMap
        );

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

            stepLogger.writeServerCall("activation-create-request-sent", uri, "POST", requestObject, headers);

            ResponseEntity<ObjectResponse<ActivationCreateResponse>> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<ObjectResponse<ActivationCreateResponse>> typeReference = new ParameterizedTypeReference<ObjectResponse<ActivationCreateResponse>>() {
            };
            try {
                responseEntity = restClient.post(uri, body, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                stepLogger.writeServerCallError("activation-create-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                stepLogger.writeDoneFailed("activation-create-failed");
                return null;
            }

            ObjectResponse<ActivationCreateResponse> responseWrapper = Objects.requireNonNull(responseEntity.getBody());

            stepLogger.writeServerCallOK("activation-create-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

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
                SecretKey signatureKnowledgeSecretKey = keyFactory.generateClientSignatureKnowledgeKey(masterSecretKey);
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
                byte[] cSignatureKnowledgeSecretKey = EncryptedStorageUtil.storeSignatureKnowledgeKey(password, signatureKnowledgeSecretKey, salt, keyGenerator);

                // Prepare the status object to be stored
                ResultStatusObject resultStatusObject = model.getResultStatus();

                resultStatusObject.setActivationId(activationId);
                resultStatusObject.getCounter().set(0L);
                resultStatusObject.setCtrDataBase(null);
                resultStatusObject.setEncryptedDevicePrivateKeyBytes(encryptedDevicePrivateKey);
                resultStatusObject.setServerPublicKeyObject(serverPublicKey);
                resultStatusObject.setSignatureBiometryKeyObject(signatureBiometrySecretKey);
                resultStatusObject.setSignatureKnowledgeKeyEncryptedBytes(cSignatureKnowledgeSecretKey);
                resultStatusObject.setSignatureKnowledgeKeySaltBytes(salt);
                resultStatusObject.setSignaturePossessionKeyObject(signaturePossessionSecretKey);
                resultStatusObject.setTransportMasterKeyObject(transportMasterKey);
                resultStatusObject.setVersion(2L);

                model.setResultStatusObject(resultStatusObject);

                // Store the resulting status
                String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatus());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(formatted);
                }

                objectMap = new HashMap<>();
                objectMap.put("activationId", activationId);
                objectMap.put("activationStatusFile", model.getStatusFileName());
                objectMap.put("activationStatusFileContent", model.getResultStatus());
                objectMap.put("deviceKeyFingerprint", activation.computeActivationFingerprint(deviceKeyPair.getPublic()));
                stepLogger.writeItem(
                        "activation-create-activation-done",
                        "Activation Done",
                        "Public key exchange was successfully completed, commit the activation on server",
                        "OK",
                        objectMap
                );
                return model.getResultStatus();

            } else {
                String message = "Activation data signature does not match. Either someone tried to spoof your connection, or your device master key is invalid.";
                stepLogger.writeError("activation-create-activation-signature-mismatch", message);
                stepLogger.writeDoneFailed("activation-create-failed");
                return null;
            }
        } catch (Exception exception) {
            stepLogger.writeError("activation-create-error-generic", exception);
            stepLogger.writeDoneFailed("activation-create-failed");
            return null;
        }
    }

}
