package io.getlime.security.powerauth.lib.cmd.steps.v2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.encryptor.ClientNonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
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
 * Class with create activation logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class CreateActivationStep implements BaseStep {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final KeyConvertor keyConvertor = new KeyConvertor();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientVault vault = new PowerAuthClientVault();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();

    @Override
    @SuppressWarnings("unchecked")
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        // Read properties from "context"
        CreateActivationStepModel model = new CreateActivationStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "create-activation-start",
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
                    "create-activation-identity-attributes",
                    "Identity Attributes",
                    "Following attributes are used to authenticate user",
                    "OK",
                    identityAttributes
            );
        }

        Map<String, Object> customAttributes = model.getCustomAttributes();
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "create-activation-custom-attributes",
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
                    "create-activation-activation-otp-use",
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
            if (activationIdShort == null) {
                if (stepLogger != null) {
                    String message = "Failed to extract parameters from query string - exiting.";
                    stepLogger.writeError("create-activation-error-query-string", message);
                    stepLogger.writeDoneFailed("create-activation-failed");
                }
                return null;
            }
        } else {
            if (stepLogger != null) {
                String message = "No identity attributes were provided - exiting.";
                stepLogger.writeError("create-activation-error-identity-attributes", message);
                stepLogger.writeDoneFailed("create-activation-failed");
            }
            return null;
        }
        if (stepLogger != null) {
            stepLogger.writeItem(
                    "create-activation-identity-string",
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
        byte[] ephemeralPublicKeyBytes = keyConvertor.convertPublicKeyToBytes(clientEphemeralKeyPair.getPublic());

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
                    "create-activation-request-prepare",
                    "Building activation request object",
                    "Following activation attributes will be encrypted and sent to the server",
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
                    "create-activation-request-encrypt",
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
                stepLogger.writeServerCall("create-activation-request-sent", uri, "POST", requestObject, headers);
            }

            HttpResponse<String> response = Unirest.post(uri)
                    .headers(headers)
                    .body(body)
                    .asString();

            if (response.getStatus() == 200) {
                TypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>> typeReference = new TypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>>() {};
                ObjectResponse<NonPersonalizedEncryptedPayloadModel> responseWrapper = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getBody(), typeReference);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK("create-activation-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));
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
                            "create-activation-response-decrypt",
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
                PublicKey ephemeralPublicKey = keyConvertor.convertBytesToPublicKey(ephemeralKeyBytes);

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
                    model.getResultStatusObject().put("activationId", activationId);
                    model.getResultStatusObject().put("serverPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));
                    model.getResultStatusObject().put("encryptedDevicePrivateKey", BaseEncoding.base64().encode(encryptedDevicePrivateKey));
                    model.getResultStatusObject().put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionSecretKey)));
                    model.getResultStatusObject().put("signatureKnowledgeKeyEncrypted", BaseEncoding.base64().encode(cSignatureKnowledgeSecretKey));
                    model.getResultStatusObject().put("signatureKnowledgeKeySalt", BaseEncoding.base64().encode(salt));
                    model.getResultStatusObject().put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometrySecretKey)));
                    model.getResultStatusObject().put("transportMasterKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(transportMasterKey)));
                    model.getResultStatusObject().put("counter", 0L);
                    model.getResultStatusObject().put("ctrData", null);
                    model.getResultStatusObject().put("version", 2L);

                    // Store the resulting status
                    String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                    try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                        file.write(formatted);
                    }

                    Map<String, Object> objectMap = new HashMap<>();
                    objectMap.put("activationId", activationId);
                    objectMap.put("activationStatusFile", model.getStatusFileName());
                    objectMap.put("activationStatusFileContent", model.getResultStatusObject());
                    objectMap.put("deviceKeyFingerprint", activation.computeActivationFingerprint(deviceKeyPair.getPublic()));
                    if (stepLogger != null) {
                        stepLogger.writeItem(
                                "create-activation-activation-done",
                                "Activation Done",
                                "Public key exchange was successfully completed, commit the activation on server if required",
                                "OK",
                                objectMap
                        );
                        stepLogger.writeDoneOK("create-activation-success");
                    }

                    return model.getResultStatusObject();

                } else {
                    if (stepLogger != null) {
                        String message = "Activation data signature does not match. Either someone tried to spoof your connection, or your device master key is invalid.";
                        stepLogger.writeError("create-activation-error-signature-data", message);
                        stepLogger.writeDoneFailed("create-activation-failed");
                    }
                    return null;
                }
            } else {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError("create-activation-error-server-call", response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                    stepLogger.writeDoneFailed("create-activation-failed");
                }
                return null;
            }

        } catch (UnirestException exception) {
            if (stepLogger != null) {
                stepLogger.writeServerCallConnectionError("create-activation-error-unirest", exception);
                stepLogger.writeDoneFailed("create-activation-failed");
            }
            return null;
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError("create-activation-error-generic", exception);
                stepLogger.writeDoneFailed("create-activation-failed");
            }
            return null;
        }
    }

}
