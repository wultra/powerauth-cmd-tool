package io.getlime.security.powerauth.lib.cmd.steps;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.encryptor.ClientNonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class CreateActivationStep implements BaseStep {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientVault vault = new PowerAuthClientVault();
    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public JSONObject execute(JsonStepLogger stepLogger, Map<String, Object> context) throws Exception {
        // Read properties from "context"
        CreateActivationStepModel model = new CreateActivationStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Activation With Custom Attributes Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the activation URI
        String uri = model.getUriString();

        // Read the identity attributes and custom attributes
        Map<String, String> identityAttributes = model.getIdentityAttributes();
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Identity Attributes",
                    "Following attributes are used to authenticate user",
                    "OK",
                    identityAttributes
            );
        }

        Map<String, Object> customAttributes = model.getCustomAttributes();
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Custom Attributes",
                    "Following attributes are used as custom attributes for the request",
                    "OK",
                    customAttributes
            );
        }

        // Get activation OTP, use default "zero code" in case no OTP is provided
        String activationOTP = "00000-00000";
        if (model.getActivationOtp() != null) {
            activationOTP = model.getActivationOtp();
        }
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Using activation OTP",
                    "Following string is used as activation OTP ('00000-00000' is used by default)'",
                    "OK",
                    activationOTP
            );
        }

        // Build the normalized identity string
        String activationIdShort = null;
        for (String key: identityAttributes.keySet()) {
            String value = identityAttributes.get(key);
            String pair = URLEncoder.encode(key, "UTF-8") + "=" + URLEncoder.encode(value, "UTF-8");
            if (activationIdShort == null) {
                activationIdShort = pair; // initialize with the first key/value
            } else {
                activationIdShort = activationIdShort + "&" + pair;
            }
        }
        if (activationIdShort != null) {
            activationIdShort = PowerAuthRequestCanonizationUtils.canonizeGetParameters(activationIdShort);
        } else {
            if (stepLogger != null) {
                String message = "No identity attributes were provided - exiting.";
                stepLogger.writeError(message);
                stepLogger.writeDoneFailed();
            }
            return null;
        }
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Building identity string",
                    "Using following normalized identity string",
                    "OK",
                    activationIdShort
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
        ActivationCreateRequest powerauth = new ActivationCreateRequest();
        powerauth.setActivationIdShort(activationIdShort);
        powerauth.setApplicationKey(model.getApplicationKey());
        powerauth.setActivationName(model.getActivationName());
        powerauth.setActivationNonce(BaseEncoding.base64().encode(nonceDeviceBytes));
        powerauth.setEphemeralPublicKey(BaseEncoding.base64().encode(ephemeralPublicKeyBytes));
        powerauth.setEncryptedDevicePublicKey(BaseEncoding.base64().encode(cDevicePublicKeyBytes));
        powerauth.setApplicationSignature(BaseEncoding.base64().encode(signature));

        ActivationCreateCustomRequest requestObject = new ActivationCreateCustomRequest();
        requestObject.setIdentity(identityAttributes);
        requestObject.setCustomAttributes(customAttributes);
        requestObject.setPowerauth(powerauth);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Building activation request object",
                    "Following activation attributes will be encrypted and send to the server",
                    "OK",
                    requestObject
            );
        }

        // Convert the object to bytes
        byte[] requestObjectBytes = mapper.writeValueAsBytes(requestObject);

        // Prepare the encryptor
        ClientNonPersonalizedEncryptor encryptor = new ClientNonPersonalizedEncryptor(BaseEncoding.base64().decode(model.getApplicationKey()), model.getMasterPublicKey());

        // Encrypt the bytes
        final NonPersonalizedEncryptedMessage encryptedMessage = encryptor.encrypt(requestObjectBytes);
        NonPersonalizedEncryptedPayloadModel encryptedRequestObject = new NonPersonalizedEncryptedPayloadModel();
        encryptedRequestObject.setAdHocIndex(BaseEncoding.base64().encode(encryptedMessage.getAdHocIndex()));
        encryptedRequestObject.setApplicationKey(BaseEncoding.base64().encode(encryptedMessage.getApplicationKey()));
        encryptedRequestObject.setEncryptedData(BaseEncoding.base64().encode(encryptedMessage.getEncryptedData()));
        encryptedRequestObject.setEphemeralPublicKey(BaseEncoding.base64().encode(encryptedMessage.getEphemeralPublicKey()));
        encryptedRequestObject.setMac(BaseEncoding.base64().encode(encryptedMessage.getMac()));
        encryptedRequestObject.setMacIndex(BaseEncoding.base64().encode(encryptedMessage.getMacIndex()));
        encryptedRequestObject.setNonce(BaseEncoding.base64().encode(encryptedMessage.getNonce()));
        encryptedRequestObject.setSessionIndex(BaseEncoding.base64().encode(encryptedMessage.getSessionIndex()));

        ObjectRequest<NonPersonalizedEncryptedPayloadModel> body = new ObjectRequest<>();
        body.setRequestObject(encryptedRequestObject);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Encrypting request object",
                    "Following encrypted object is used for activation",
                    "OK",
                    body
            );
        }

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
                TypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>> typeReference = new TypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>>() {};
                ObjectResponse<NonPersonalizedEncryptedPayloadModel> responseWrapper = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getRawBody(), typeReference);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                // Decrypt the server response
                final NonPersonalizedEncryptedPayloadModel encryptedResponseObject = responseWrapper.getResponseObject();
                encryptedMessage.setApplicationKey(BaseEncoding.base64().decode(encryptedResponseObject.getApplicationKey()));
                encryptedMessage.setAdHocIndex(BaseEncoding.base64().decode(encryptedResponseObject.getAdHocIndex()));
                encryptedMessage.setEphemeralPublicKey(BaseEncoding.base64().decode(encryptedResponseObject.getEphemeralPublicKey()));
                encryptedMessage.setEncryptedData(BaseEncoding.base64().decode(encryptedResponseObject.getEncryptedData()));
                encryptedMessage.setMac(BaseEncoding.base64().decode(encryptedResponseObject.getMac()));
                encryptedMessage.setMacIndex(BaseEncoding.base64().decode(encryptedResponseObject.getMacIndex()));
                encryptedMessage.setNonce(BaseEncoding.base64().decode(encryptedResponseObject.getNonce()));
                encryptedMessage.setSessionIndex(BaseEncoding.base64().decode(encryptedResponseObject.getSessionIndex()));
                byte[] originalResponseObjectBytes = encryptor.decrypt(encryptedMessage);
                ActivationCreateResponse responseObject = mapper.readValue(originalResponseObjectBytes, ActivationCreateResponse.class);

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Decrypted response",
                            "Following activation data were decrypted",
                            "OK",
                            responseObject
                    );
                }

                // Process the response object
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
                    byte[] cSignatureKnoweldgeSecretKey = EncryptedStorageUtil.storeSignatureKnowledgeKey(password, signatureKnoweldgeSecretKey, salt, keyGenerator);

                    // Prepare the status object to be stored
                    model.getResultStatusObject().put("activationId", activationId);
                    model.getResultStatusObject().put("serverPublicKey", BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(serverPublicKey)));
                    model.getResultStatusObject().put("encryptedDevicePrivateKey", BaseEncoding.base64().encode(encryptedDevicePrivateKey));
                    model.getResultStatusObject().put("signaturePossessionKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signaturePossessionSecretKey)));
                    model.getResultStatusObject().put("signatureKnowledgeKeyEncrypted", BaseEncoding.base64().encode(cSignatureKnoweldgeSecretKey));
                    model.getResultStatusObject().put("signatureKnowledgeKeySalt", BaseEncoding.base64().encode(salt));
                    model.getResultStatusObject().put("signatureBiometryKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(signatureBiometrySecretKey)));
                    model.getResultStatusObject().put("transportMasterKey", BaseEncoding.base64().encode(keyConversion.convertSharedSecretKeyToBytes(transportMasterKey)));
                    model.getResultStatusObject().put("counter", 0);

                    // Store the resulting status
                    String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                    try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                        file.write(formatted);
                    }

                    Map<String, Object> objectMap = new HashMap<>();
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
