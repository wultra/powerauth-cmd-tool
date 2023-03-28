package io.getlime.security.powerauth.lib.cmd.steps.v2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
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
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

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
@Component(value = "createActivationStepV2")
public class CreateActivationStep extends AbstractBaseStepV2 {

    /**
     * Constructor
     * @param stepLogger Step logger
     */
    @Autowired
    public CreateActivationStep(StepLogger stepLogger) {
        super(PowerAuthStep.ACTIVATION_CREATE_CUSTOM, PowerAuthVersion.VERSION_2, stepLogger);
    }

    /**
     * Constructor for backward compatibility
     */
    public CreateActivationStep() {
        this(DEFAULT_STEP_LOGGER);
    }

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final KeyConvertor keyConvertor = new KeyConvertor();
    private static final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientVault vault = new PowerAuthClientVault();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();

    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(Map<String, Object> context) throws Exception {
        // Read properties from "context"
        CreateActivationStepModel model = new CreateActivationStepModel();
        model.fromMap(context);

        // Prepare the activation URI
        String uri = model.getUriString();

        // Read the identity attributes and custom attributes
        Map<String, String> identityAttributes = model.getIdentityAttributes();
        stepLogger.writeItem(
                "activation-create-custom-identity-attributes",
                "Identity Attributes",
                "Following attributes are used to authenticate user",
                "OK",
                identityAttributes
        );

        Map<String, Object> customAttributes = model.getCustomAttributes();
        stepLogger.writeItem(
                "activation-create-custom-custom-attributes",
                "Custom Attributes",
                "Following attributes are used as custom attributes for the request",
                "OK",
                customAttributes
        );

        // Get activation OTP, use default "zero code" in case no OTP is provided
        String activationOTP = "00000-00000";
        if (model.getActivationOtp() != null) {
            activationOTP = model.getActivationOtp();
        }
        stepLogger.writeItem(
                "activation-create-custom-activation-otp-use",
                "Using activation OTP",
                "Following string is used as activation OTP ('00000-00000' is used by default)'",
                "OK",
                activationOTP
        );

        // Build the normalized identity string
        String activationIdShort = null;
        for (String key : identityAttributes.keySet()) {
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
                String message = "Failed to extract parameters from query string - exiting.";
                stepLogger.writeError("activation-create-custom-error-query-string", message);
                stepLogger.writeDoneFailed("activation-create-custom-failed");
                return null;
            }
        } else {
            String message = "No identity attributes were provided - exiting.";
            stepLogger.writeError("activation-create-custom-error-identity-attributes", message);
            stepLogger.writeDoneFailed("activation-create-custom-failed");
            return null;
        }
        stepLogger.writeItem(
                "activation-create-custom-identity-string",
                "Building identity string",
                "Using following normalized identity string",
                "OK",
                activationIdShort
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
                Base64.getDecoder().decode(model.getApplicationKey()),
                Base64.getDecoder().decode(model.getApplicationSecret())
        );
        byte[] ephemeralPublicKeyBytes = keyConvertor.convertPublicKeyToBytes(clientEphemeralKeyPair.getPublic());

        // Prepare the server request
        ActivationCreateRequest powerauth = new ActivationCreateRequest();
        powerauth.setActivationIdShort(activationIdShort);
        powerauth.setApplicationKey(model.getApplicationKey());
        powerauth.setActivationName(model.getActivationName());
        powerauth.setActivationNonce(Base64.getEncoder().encodeToString(nonceDeviceBytes));
        powerauth.setEphemeralPublicKey(Base64.getEncoder().encodeToString(ephemeralPublicKeyBytes));
        powerauth.setEncryptedDevicePublicKey(Base64.getEncoder().encodeToString(cDevicePublicKeyBytes));
        powerauth.setApplicationSignature(Base64.getEncoder().encodeToString(signature));

        ActivationCreateCustomRequest requestObject = new ActivationCreateCustomRequest();
        requestObject.setIdentity(identityAttributes);
        requestObject.setCustomAttributes(customAttributes);
        requestObject.setPowerauth(powerauth);

        stepLogger.writeItem(
                "activation-create-custom-request-prepare",
                "Building activation request object",
                "Following activation attributes will be encrypted and sent to the server",
                "OK",
                requestObject
        );

        // Convert the object to bytes
        byte[] requestObjectBytes = mapper.writeValueAsBytes(requestObject);

        // Prepare the encryptor
        ClientNonPersonalizedEncryptor encryptor = new ClientNonPersonalizedEncryptor(Base64.getDecoder().decode(model.getApplicationKey()), model.getMasterPublicKey());

        // Encrypt the bytes
        final NonPersonalizedEncryptedMessage encryptedMessage = encryptor.encrypt(requestObjectBytes);
        NonPersonalizedEncryptedPayloadModel encryptedRequestObject = new NonPersonalizedEncryptedPayloadModel();
        encryptedRequestObject.setAdHocIndex(Base64.getEncoder().encodeToString(encryptedMessage.getAdHocIndex()));
        encryptedRequestObject.setApplicationKey(Base64.getEncoder().encodeToString(encryptedMessage.getApplicationKey()));
        encryptedRequestObject.setEncryptedData(Base64.getEncoder().encodeToString(encryptedMessage.getEncryptedData()));
        encryptedRequestObject.setEphemeralPublicKey(Base64.getEncoder().encodeToString(encryptedMessage.getEphemeralPublicKey()));
        encryptedRequestObject.setMac(Base64.getEncoder().encodeToString(encryptedMessage.getMac()));
        encryptedRequestObject.setMacIndex(Base64.getEncoder().encodeToString(encryptedMessage.getMacIndex()));
        encryptedRequestObject.setNonce(Base64.getEncoder().encodeToString(encryptedMessage.getNonce()));
        encryptedRequestObject.setSessionIndex(Base64.getEncoder().encodeToString(encryptedMessage.getSessionIndex()));

        ObjectRequest<NonPersonalizedEncryptedPayloadModel> body = new ObjectRequest<>();
        body.setRequestObject(encryptedRequestObject);

        stepLogger.writeItem(
                "activation-create-custom-request-encrypt",
                "Encrypting request object",
                "Following encrypted object is used for activation",
                "OK",
                body
        );

        // Call the server with activation data
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.putAll(model.getHeaders());

            stepLogger.writeServerCall("activation-create-custom-request-sent", uri, "POST", requestObject, requestObjectBytes, headers);
            ResponseEntity<ObjectResponse<NonPersonalizedEncryptedPayloadModel>> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>> typeReference = new ParameterizedTypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>>() {
            };
            try {
                responseEntity = restClient.post(uri, body, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                stepLogger.writeServerCallError("activation-create-custom-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                stepLogger.writeDoneFailed("activation-create-custom-failed");
                return null;
            }

            ObjectResponse<NonPersonalizedEncryptedPayloadModel> responseWrapper = Objects.requireNonNull(responseEntity.getBody());

            stepLogger.writeServerCallOK("activation-create-custom-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

            // Decrypt the server response
            final NonPersonalizedEncryptedPayloadModel encryptedResponseObject = responseWrapper.getResponseObject();
            encryptedMessage.setApplicationKey(Base64.getDecoder().decode(encryptedResponseObject.getApplicationKey()));
            encryptedMessage.setAdHocIndex(Base64.getDecoder().decode(encryptedResponseObject.getAdHocIndex()));
            encryptedMessage.setEphemeralPublicKey(Base64.getDecoder().decode(encryptedResponseObject.getEphemeralPublicKey()));
            encryptedMessage.setEncryptedData(Base64.getDecoder().decode(encryptedResponseObject.getEncryptedData()));
            encryptedMessage.setMac(Base64.getDecoder().decode(encryptedResponseObject.getMac()));
            encryptedMessage.setMacIndex(Base64.getDecoder().decode(encryptedResponseObject.getMacIndex()));
            encryptedMessage.setNonce(Base64.getDecoder().decode(encryptedResponseObject.getNonce()));
            encryptedMessage.setSessionIndex(Base64.getDecoder().decode(encryptedResponseObject.getSessionIndex()));
            byte[] originalResponseObjectBytes = encryptor.decrypt(encryptedMessage);
            ActivationCreateResponse responseObject = mapper.readValue(originalResponseObjectBytes, ActivationCreateResponse.class);

            stepLogger.writeItem(
                    "activation-create-custom-response-decrypt",
                    "Decrypted response",
                    "Following activation data were decrypted",
                    "OK",
                    responseObject
            );

            // Process the response object
            String activationId = responseObject.getActivationId();
            byte[] nonceServerBytes = Base64.getDecoder().decode(responseObject.getActivationNonce());
            byte[] cServerPubKeyBytes = Base64.getDecoder().decode(responseObject.getEncryptedServerPublicKey());
            byte[] cServerPubKeySignatureBytes = Base64.getDecoder().decode(responseObject.getEncryptedServerPublicKeySignature());
            byte[] ephemeralKeyBytes = Base64.getDecoder().decode(responseObject.getEphemeralPublicKey());
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
                ResultStatusObject resultStatusObject = model.getResultStatus();

                resultStatusObject.setActivationId(activationId);
                resultStatusObject.setCounter(0L);
                resultStatusObject.setCtrData(null);
                resultStatusObject.setEncryptedDevicePrivateKeyBytes(encryptedDevicePrivateKey);
                resultStatusObject.setServerPublicKeyObject(serverPublicKey);
                resultStatusObject.setSignatureBiometryKeyObject(signatureBiometrySecretKey);
                resultStatusObject.setSignatureKnowledgeKeyEncryptedBytes(cSignatureKnowledgeSecretKey);
                resultStatusObject.setSignatureKnowledgeKeySaltBytes(salt);
                resultStatusObject.setSignaturePossessionKeyObject(signaturePossessionSecretKey);
                resultStatusObject.setTransportMasterKeyObject(transportMasterKey);
                resultStatusObject.setVersion(2L);

                model.setResultStatus(resultStatusObject);

                // Store the resulting status
                String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatus());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(formatted);
                }

                Map<String, Object> objectMap = new HashMap<>();
                objectMap.put("activationId", activationId);
                objectMap.put("activationStatusFile", model.getStatusFileName());
                objectMap.put("activationStatusFileContent", model.getResultStatus());
                objectMap.put("deviceKeyFingerprint", activation.computeActivationFingerprint(deviceKeyPair.getPublic()));

                stepLogger.writeItem(
                        "activation-create-custom-activation-done",
                        "Activation Done",
                        "Public key exchange was successfully completed, commit the activation on server if required",
                        "OK",
                        objectMap
                );
                stepLogger.writeDoneOK("activation-create-custom-success");

                return model.getResultStatus();
            } else {
                String message = "Activation data signature does not match. Either someone tried to spoof your connection, or your device master key is invalid.";
                stepLogger.writeError("activation-create-custom-error-signature-data", message);
                stepLogger.writeDoneFailed("activation-create-custom-failed");
                return null;
            }
        } catch (Exception exception) {
            stepLogger.writeError("activation-create-custom-error-generic", exception);
            stepLogger.writeDoneFailed("activation-create-custom-failed");
            return null;
        }
    }

}
