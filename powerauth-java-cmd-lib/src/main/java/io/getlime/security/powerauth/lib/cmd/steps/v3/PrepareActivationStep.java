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
package io.getlime.security.powerauth.lib.cmd.steps.v3;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationVersion;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer2Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class with prepare activation logic.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *      <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PrepareActivationStep implements BaseStep {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientVault vault = new PowerAuthClientVault();

    private final EciesFactory eciesFactory = new EciesFactory();
    private final ObjectMapper mapper = RestClientConfiguration.defaultMapper();

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
        String uri = model.getUriString() + "/pa/v3/activation/create";

        // Fetch and parse the activation code
        Pattern p = Pattern.compile("^[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}$");
        Matcher m = p.matcher(model.getActivationCode());
        if (!m.find()) {
            if (stepLogger != null) {
                stepLogger.writeError("Prepare activation step failed", "Activation code has invalid format");
                stepLogger.writeDoneFailed();
                return null;
            }
        }
        final String activationCode = model.getActivationCode();

        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationCode", activationCode);
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Activation code",
                    "Storing activation code",
                    "OK",
                    objectMap
            );
        }

        // Get activation key and secret
        final String applicationKey = model.getApplicationKey();
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

        // Generate device key pair
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConversion.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = BaseEncoding.base64().encode(devicePublicKeyBytes);

        // Create activation layer 2 request which is decryptable only on PowerAuth server
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(model.getActivationName());
        requestL2.setDevicePublicKey(devicePublicKeyBase64);

        // Encrypt request data using ECIES in application scope with sharedInfo1 = /pa/activation
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        mapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray());

        // Prepare the encrypted layer 2 request
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(BaseEncoding.base64().encode(eciesCryptogramL2.getMac()));

        // Prepare activation layer 1 request which is decryptable on intermediate server
        ActivationLayer1Request requestL1 = new ActivationLayer1Request();
        requestL1.setType(ActivationType.CODE);
        requestL1.setActivationData(encryptedRequestL2);
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("code", activationCode);
        requestL1.setIdentityAttributes(identityAttributes);

        // Encrypt the layer 1 request using ECIES in application scope with sharedInfo1 = /pa/generic/application
        EciesEncryptor eciesEncryptorL1 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC);
        ByteArrayOutputStream baosL1 = new ByteArrayOutputStream();
        mapper.writeValue(baosL1, requestL1);
        EciesCryptogram eciesCryptogramL1 = eciesEncryptorL1.encryptRequest(baosL1.toByteArray());

        // Prepare the encrypted layer 1 request
        EciesEncryptedRequest encryptedRequestL1 = new EciesEncryptedRequest();
        encryptedRequestL1.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL1.getEphemeralPublicKey()));
        encryptedRequestL1.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL1.getEncryptedData()));
        encryptedRequestL1.setMac(BaseEncoding.base64().encode(eciesCryptogramL1.getMac()));

        // Prepare the encryption header
        PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader(applicationKey, model.getVersion());
        String httpEncryptionHeader = header.buildHttpHeader();

        // Call the server with encrypted activation request
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthEncryptionHttpHeader.HEADER_NAME, httpEncryptionHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall(uri, "POST", encryptedRequestL1, headers);
            }

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(encryptedRequestL1)
                    .asString();

            if (response.getStatus() == 200) {
                EciesEncryptedResponse encryptedResponseL1 = mapper.readValue(response.getRawBody(), EciesEncryptedResponse.class);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(encryptedResponseL1, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                // Read activation layer 1 response and decrypt it
                byte[] macL1 = BaseEncoding.base64().decode(encryptedResponseL1.getMac());
                byte[] encryptedDataL1 = BaseEncoding.base64().decode(encryptedResponseL1.getEncryptedData());
                EciesCryptogram responseCryptogramL1 = new EciesCryptogram(macL1, encryptedDataL1);
                byte[] decryptedDataL1 = eciesEncryptorL1.decryptResponse(responseCryptogramL1);

                // Read activation layer 1 response from data
                ActivationLayer1Response responseL1 = mapper.readValue(decryptedDataL1, ActivationLayer1Response.class);

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Decrypted Layer 1 Response",
                            "Following layer 1 activation data were decrypted",
                            "OK",
                            responseL1
                    );
                }

                // Decrypt layer 2 response
                byte[] macL2 = BaseEncoding.base64().decode(responseL1.getActivationData().getMac());
                byte[] encryptedDataL2 = BaseEncoding.base64().decode(responseL1.getActivationData().getEncryptedData());
                EciesCryptogram responseCryptogramL2 = new EciesCryptogram(macL2, encryptedDataL2);
                byte[] decryptedDataL2 = eciesEncryptorL2.decryptResponse(responseCryptogramL2);

                // Convert activation layer 2 response from JSON to object and extract activation parameters
                ActivationLayer2Response responseL2 = mapper.readValue(decryptedDataL2, ActivationLayer2Response.class);

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Decrypted Layer 2 Response",
                            "Following layer 2 activation data were decrypted",
                            "OK",
                            responseL2
                    );
                }

                String activationId = responseL2.getActivationId();
                String ctrDataBase64 = responseL2.getCtrData();
                String serverPublicKeyBase64 = responseL2.getServerPublicKey();
                PublicKey serverPublicKey = keyConversion.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));

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
                model.getResultStatusObject().put("activationId", activationId);
                model.getResultStatusObject().put("serverPublicKey", BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(serverPublicKey)));
                model.getResultStatusObject().put("encryptedDevicePrivateKey", BaseEncoding.base64().encode(encryptedDevicePrivateKey));
                model.getResultStatusObject().put("signaturePossessionKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signaturePossessionSecretKey)));
                model.getResultStatusObject().put("signatureKnowledgeKeyEncrypted", BaseEncoding.base64().encode(cSignatureKnowledgeSecretKey));
                model.getResultStatusObject().put("signatureKnowledgeKeySalt", BaseEncoding.base64().encode(salt));
                model.getResultStatusObject().put("signatureBiometryKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signatureBiometrySecretKey)));
                model.getResultStatusObject().put("transportMasterKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(transportMasterKey)));
                model.getResultStatusObject().put("counter", 0L);
                model.getResultStatusObject().put("ctrData", ctrDataBase64);
                model.getResultStatusObject().put("version", 3L);

                // Store the resulting status
                String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(formatted);
                }

                objectMap = new HashMap<>();
                objectMap.put("activationId", activationId);
                objectMap.put("activationStatusFile", model.getStatusFileName());
                objectMap.put("activationStatusFileContent", model.getResultStatusObject());
                objectMap.put("deviceKeyFingerprint", activation.computeActivationFingerprint(deviceKeyPair.getPublic(), serverPublicKey, activationId));
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
