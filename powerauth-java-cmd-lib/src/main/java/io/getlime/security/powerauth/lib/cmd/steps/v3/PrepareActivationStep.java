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
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ActivationContext;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer2Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;

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
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class with prepare activation logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PrepareActivationStep implements BaseStep {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final KeyConvertor keyConvertor = new KeyConvertor();
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
    public ResultStatusObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "activation-prepare-start",
                    "Activation Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/v3/activation/create";
        final String applicationKey = model.getApplicationKey();

        // Get activation key and secret
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

        EciesEncryptor eciesEncryptorL1 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC);
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.ACTIVATION_LAYER_2);

        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();

        ActivationContext stepContext = ActivationContext.builder()
                .deviceKeyPair(deviceKeyPair)
                .eciesEncryptorL1(eciesEncryptorL1)
                .eciesEncryptorL2(eciesEncryptorL2)
                .modelPrepare(model)
                .password(model.getPassword())
                .resultStatusObject(model.getResultStatusObject())
                .stepLogger(stepLogger)
                .build();

        EciesEncryptedRequest encryptedRequestL1 = createRequest(stepContext);

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
                stepLogger.writeServerCall("activation-create-request-sent", uri, "POST", encryptedRequestL1, headers);
            }

            ResponseEntity<EciesEncryptedResponse> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<EciesEncryptedResponse> typeReference = new ParameterizedTypeReference<EciesEncryptedResponse>() {};
            try {
                responseEntity = restClient.post(uri, encryptedRequestL1, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError("activation-create-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                    stepLogger.writeDoneFailed("activation-create-failed");
                }
                return null;
            }

            EciesEncryptedResponse encryptedResponseL1 = Objects.requireNonNull(responseEntity.getBody());
            if (stepLogger != null) {
                stepLogger.writeServerCallOK("activation-create-response-received", encryptedResponseL1, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));
            }

            ResultStatusObject resultStatusObject = processResponse(encryptedResponseL1, stepContext);
            model.setResultStatusObject(resultStatusObject);

            // Store the resulting status
            String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
            try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                file.write(formatted);
            }

            Map<String, Object> objectMap = new HashMap<>();
            objectMap.put("activationId", resultStatusObject.getActivationId());
            objectMap.put("activationStatusFile", model.getStatusFileName());
            objectMap.put("activationStatusFileContent", model.getResultStatusObject());
            objectMap.put("deviceKeyFingerprint", activation.computeActivationFingerprint(deviceKeyPair.getPublic(), resultStatusObject.getServerPublicKey(), resultStatusObject.getActivationId()));
            if (stepLogger != null) {
                stepLogger.writeItem(
                        "activation-create-activation-done",
                        "Activation Done",
                        "Public key exchange was successfully completed, commit the activation on server",
                        "OK",
                        objectMap
                );
                stepLogger.writeDoneOK("activation-create-success");
            }

            return model.getResultStatusObject();
        } catch (Exception ex) {
            if (stepLogger != null) {
                stepLogger.writeError("activation-create-error-generic", ex);
                stepLogger.writeDoneFailed("activation-create-failed");
            }
            return null;
        }
    }

    public EciesEncryptedRequest createRequest(ActivationContext stepContext) throws Exception {
        PrepareActivationStepModel model = stepContext.getModelPrepare();
        StepLogger stepLogger = stepContext.getStepLogger();

        // Fetch and parse the activation code
        Pattern p = Pattern.compile("^[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}$");
        Matcher m = p.matcher(model.getActivationCode());
        if (!m.find()) {
            if (stepLogger != null) {
                stepLogger.writeError("activation-create-activation-code", "Prepare activation step failed", "Activation code has invalid format");
                stepLogger.writeDoneFailed("activation-create-error-activation-code");
                return null;
            }
        }
        final String activationCode = model.getActivationCode();

        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationCode", activationCode);
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "activation-create-activation-code",
                    "Activation code",
                    "Storing activation code",
                    "OK",
                    objectMap
            );

        }

        // Generate device key pair
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(stepContext.getDeviceKeyPair().getPublic());
        String devicePublicKeyBase64 = BaseEncoding.base64().encode(devicePublicKeyBytes);

        // Create activation layer 2 request which is decryptable only on PowerAuth server
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(model.getActivationName());
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        requestL2.setPlatform(model.getPlatform());
        requestL2.setDeviceInfo(model.getDeviceInfo());

        // Get activation key and secret
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

        // Encrypt request data using ECIES in application scope with sharedInfo1 = /pa/activation
        final boolean useIv = !"3.0".equals(model.getVersion());
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        mapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = stepContext.getEciesEncryptorL2().encryptRequest(baosL2.toByteArray(), useIv);

        // Prepare the encrypted layer 2 request
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(BaseEncoding.base64().encode(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(useIv ? BaseEncoding.base64().encode(eciesCryptogramL2.getNonce()) : null);

        // Prepare activation layer 1 request which is decryptable on intermediate server
        ActivationLayer1Request requestL1 = new ActivationLayer1Request();
        requestL1.setType(ActivationType.CODE);
        requestL1.setActivationData(encryptedRequestL2);
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("code", activationCode);
        requestL1.setIdentityAttributes(identityAttributes);

        if (stepContext.getStepLogger() != null) {
            stepContext.getStepLogger().writeItem(
                    "activation-create-request-encrypt",
                    "Building activation request object",
                    "Following activation attributes will be encrypted and sent to the server",
                    "OK",
                    requestL1
            );
        }

        // Encrypt the layer 1 request using ECIES in application scope with sharedInfo1 = /pa/generic/application
        ByteArrayOutputStream baosL1 = new ByteArrayOutputStream();
        mapper.writeValue(baosL1, requestL1);
        EciesCryptogram eciesCryptogramL1 = stepContext.getEciesEncryptorL1().encryptRequest(baosL1.toByteArray(), useIv);

        // Prepare the encrypted layer 1 request
        EciesEncryptedRequest encryptedRequestL1 = new EciesEncryptedRequest();
        encryptedRequestL1.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL1.getEphemeralPublicKey()));
        encryptedRequestL1.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL1.getEncryptedData()));
        encryptedRequestL1.setMac(BaseEncoding.base64().encode(eciesCryptogramL1.getMac()));
        encryptedRequestL1.setNonce(useIv ? BaseEncoding.base64().encode(eciesCryptogramL1.getNonce()) : null);

        return encryptedRequestL1;
    }

    public ResultStatusObject processResponse(EciesEncryptedResponse encryptedResponseL1,
                                              ActivationContext context) throws Exception {
        // Read activation layer 1 response and decrypt it
        byte[] macL1 = BaseEncoding.base64().decode(encryptedResponseL1.getMac());
        byte[] encryptedDataL1 = BaseEncoding.base64().decode(encryptedResponseL1.getEncryptedData());
        EciesCryptogram responseCryptogramL1 = new EciesCryptogram(macL1, encryptedDataL1);
        byte[] decryptedDataL1 = context.getEciesEncryptorL1().decryptResponse(responseCryptogramL1);

        // Read activation layer 1 response from data
        ActivationLayer1Response responseL1 = mapper.readValue(decryptedDataL1, ActivationLayer1Response.class);

        if (context.getStepLogger() != null) {
            context.getStepLogger().writeItem(
                    "activation-response-decrypt",
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
        byte[] decryptedDataL2 = context.getEciesEncryptorL2().decryptResponse(responseCryptogramL2);

        // Convert activation layer 2 response from JSON to object and extract activation parameters
        ActivationLayer2Response responseL2 = mapper.readValue(decryptedDataL2, ActivationLayer2Response.class);

        if (context.getStepLogger() != null) {
            context.getStepLogger().writeItem(
                    "activation-create-response-decrypt-inner",
                    "Decrypted Layer 2 Response (changed)",
                    "Following layer 2 activation data were decrypted",
                    "OK",
                    responseL2
            );
        }

        String activationId = responseL2.getActivationId();
        String ctrDataBase64 = responseL2.getCtrData();
        String serverPublicKeyBase64 = responseL2.getServerPublicKey();
        PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));

        // Compute master secret key
        SecretKey masterSecretKey = keyFactory.generateClientMasterSecretKey(context.getDeviceKeyPair().getPrivate(), serverPublicKey);

        // Derive PowerAuth keys from master secret key
        SecretKey signaturePossessionSecretKey = keyFactory.generateClientSignaturePossessionKey(masterSecretKey);
        SecretKey signatureKnowledgeSecretKey = keyFactory.generateClientSignatureKnowledgeKey(masterSecretKey);
        SecretKey signatureBiometrySecretKey = keyFactory.generateClientSignatureBiometryKey(masterSecretKey);
        SecretKey transportMasterKey = keyFactory.generateServerTransportKey(masterSecretKey);
        // DO NOT EVER STORE ...
        SecretKey vaultUnlockMasterKey = keyFactory.generateServerEncryptedVaultKey(masterSecretKey);

        // Encrypt the original device private key using the vault unlock key
        byte[] encryptedDevicePrivateKey = vault.encryptDevicePrivateKey(context.getDeviceKeyPair().getPrivate(), vaultUnlockMasterKey);

        char[] password;
        if (context.getPassword() == null) {
            Console console = System.console();
            password = console.readPassword("Select a password to encrypt the knowledge related key: ");
        } else {
            password = context.getPassword().toCharArray();
        }

        byte[] salt = keyGenerator.generateRandomBytes(16);
        byte[] cSignatureKnowledgeSecretKey = EncryptedStorageUtil.storeSignatureKnowledgeKey(password, signatureKnowledgeSecretKey, salt, keyGenerator);

        ResultStatusObject resultStatusObject = context.getResultStatusObject();

        resultStatusObject.setActivationId(activationId);
        resultStatusObject.getCounter().set(0L);
        resultStatusObject.setCtrDataBase64(ctrDataBase64);
        resultStatusObject.setEncryptedDevicePrivateKey(encryptedDevicePrivateKey);
        resultStatusObject.setServerPublicKey(serverPublicKey);
        resultStatusObject.setSignatureBiometryKey(signatureBiometrySecretKey);
        resultStatusObject.setSignatureKnowledgeKeyEncrypted(cSignatureKnowledgeSecretKey);
        resultStatusObject.setSignatureKnowledgeKeySalt(salt);
        resultStatusObject.setSignaturePossessionKey(signaturePossessionSecretKey);
        resultStatusObject.setTransportMasterKey(transportMasterKey);
        resultStatusObject.setVersion(3L);

        return resultStatusObject;
    }

}
