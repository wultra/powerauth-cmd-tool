package com.wultra.security.powerauth.lib.cmd.util;

import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.rest.api.model.response.v4.ServerPublicKeys;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Console;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Utilities for deriving keys and populating the result status object.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public final class KeyDerivationUtil {

    private static final com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory KEY_FACTORY_V3 = new com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory();
    private static final com.wultra.security.powerauth.crypto.client.v4.keyfactory.PowerAuthClientKeyFactory KEY_FACTORY_V4 = new com.wultra.security.powerauth.crypto.client.v4.keyfactory.PowerAuthClientKeyFactory();

    private static final com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault VAULT_V3 = new com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault();
    private static final com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault VAULT_V4 = new com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    private KeyDerivationUtil() {
    }

    /**
     * Derive keys for protocol version 3.
     *
     * @param resultStatusObject        Result status object to update.
     * @param serverPublicKey           Server public key (P-256).
     * @param ecDeviceKeyPair           Device EC key pair (P-256).
     * @param knowledgeKeyPassword      Password for the knowledge key.
     * @throws InvalidKeyException      In case key is invalid.
     * @throws GenericCryptoException   In case any cryptography error occurs.
     * @throws CryptoProviderException  In case cryptography provider is initialized incorrectly.
     */
    public static void deriveKeysV3(ResultStatusObject resultStatusObject, PublicKey serverPublicKey,
                                    KeyPair ecDeviceKeyPair, String knowledgeKeyPassword) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final char[] password;
        if (knowledgeKeyPassword == null) {
            final Console console = System.console();
            password = console.readPassword("Select a password to encrypt the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = knowledgeKeyPassword.toCharArray();
        }

        final SecretKey masterSecretKey = KEY_FACTORY_V3.generateClientMasterSecretKey(ecDeviceKeyPair.getPrivate(), serverPublicKey);

        // Derive PowerAuth keys from master secret key
        final SecretKey knowledgeFactorKey = KEY_FACTORY_V3.generateClientKnowledgeFactorKey(masterSecretKey);
        final SecretKey possessionFactorKey = KEY_FACTORY_V3.generateClientPossessionFactorKey(masterSecretKey);
        final SecretKey biometryFactorKey = KEY_FACTORY_V3.generateClientBiometryFactorKey(masterSecretKey);
        final SecretKey transportMasterKey = KEY_FACTORY_V3.generateServerTransportKey(masterSecretKey);
        // DO NOT EVER STORE ...
        final SecretKey vaultUnlockMasterKey = KEY_FACTORY_V3.generateServerEncryptedVaultKey(masterSecretKey);

        final byte[] salt = KEY_GENERATOR.generateRandomBytes(16);
        final byte[] cKnowledgeFactorSecretKey = EncryptedStorageUtil.storeKnowledgeFactorKey(password, knowledgeFactorKey, salt, KEY_GENERATOR);

        // Encrypt the original device private key using the vault unlock key
        final byte[] encryptedDevicePrivateKey = VAULT_V3.encryptDevicePrivateKey(ecDeviceKeyPair.getPrivate(), vaultUnlockMasterKey);

        resultStatusObject.setEncryptedEcDevicePrivateKeyBytes(encryptedDevicePrivateKey);
        resultStatusObject.setEcServerPublicKeyObject(serverPublicKey);
        resultStatusObject.setBiometryFactorKeyObject(biometryFactorKey);
        resultStatusObject.setKnowledgeFactorKeyEncryptedBytes(cKnowledgeFactorSecretKey);
        resultStatusObject.setKnowledgeFactorKeySaltBytes(salt);
        resultStatusObject.setPossessionFactorKeyObject(possessionFactorKey);
        resultStatusObject.setTransportMasterKeyObject(transportMasterKey);
        resultStatusObject.setEcDevicePublicKeyObject(ecDeviceKeyPair.getPublic());
    }

    /**
     * Derive keys for protocol version 4.
     *
     * @param activationSharedSecret    Activation shared secret key.
     * @param resultStatusObject        Result status object to update.
     * @param serverPublicKeys          Server public keys (ECDSA + optional ML-DSA).
     * @param ecDeviceKeyPair           Device EC key pair (P-384).
     * @param pqcDeviceKeyPair          Device PQC key pair (optional).
     * @param knowledgeKeyPassword      Password for the knowledge key.
     * @throws InvalidKeyException      In case key is invalid.
     * @throws GenericCryptoException   In case any cryptography error occurs.
     * @throws CryptoProviderException  In case cryptography provider is initialized incorrectly.
     */
    public static void deriveKeysV4(SecretKey activationSharedSecret, ResultStatusObject resultStatusObject, ServerPublicKeys serverPublicKeys,
            KeyPair ecDeviceKeyPair, KeyPair pqcDeviceKeyPair, String knowledgeKeyPassword) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        final char[] password;
        if (knowledgeKeyPassword == null) {
            final Console console = System.console();
            password = console.readPassword("Select a password to encrypt the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = knowledgeKeyPassword.toCharArray();
        }

        final SecretKey tempKeyActSign = KEY_FACTORY_V4.generateKeyMacGetActTempKey(activationSharedSecret);
        final SecretKey keyStatusMac = KEY_FACTORY_V4.generateKeyMacStatus(activationSharedSecret);
        final SecretKey sharedInfo2Key = KEY_FACTORY_V4.generateSharedInfo2Key(activationSharedSecret);
        final SecretKey possessionKey = KEY_FACTORY_V4.generatePossessionFactorKey(activationSharedSecret);
        final SecretKey knowledgeKey = KEY_FACTORY_V4.generateKnowledgeFactorKey(activationSharedSecret);
        final SecretKey biometryKey = KEY_FACTORY_V4.generateBiometryFactorKey(activationSharedSecret);
        final SecretKey vaultKekDevicePriv = KEY_FACTORY_V4.generateKeyKekDevicePrivate(activationSharedSecret);

        final byte[] encEcPriv = VAULT_V4.encryptEcDevicePrivateKey(ecDeviceKeyPair.getPrivate(), vaultKekDevicePriv);
        final byte[] encPqcPriv = pqcDeviceKeyPair != null ? VAULT_V4.encryptPqcDevicePrivateKey(pqcDeviceKeyPair.getPrivate(), vaultKekDevicePriv) : null;

        // Encrypt knowledge factor key
        final byte[] knowledgeKeySalt = KEY_GENERATOR.generateRandomBytes(16);
        final byte[] encryptedKnowledgeKey = EncryptedStorageUtil.storeKnowledgeFactorKey(password, knowledgeKey, knowledgeKeySalt, KEY_GENERATOR);

        resultStatusObject.setTemporaryKeyActSignRequestKeyObject(tempKeyActSign);
        resultStatusObject.setStatusBlobMacKeyObject(keyStatusMac);
        resultStatusObject.setSharedInfo2KeyObject(sharedInfo2Key);
        resultStatusObject.setEcServerPublicKey(serverPublicKeys.getEcdsa());
        if (serverPublicKeys.getMldsa() != null) {
            resultStatusObject.setPqcServerPublicKey(serverPublicKeys.getMldsa());
        }
        resultStatusObject.setEncryptedEcDevicePrivateKeyBytes(encEcPriv);
        if (encPqcPriv != null) {
            resultStatusObject.setEncryptedPqcDevicePrivateKeyBytes(encPqcPriv);
        }
        resultStatusObject.setBiometryFactorKeyObject(biometryKey);
        resultStatusObject.setKnowledgeFactorKeyEncryptedBytes(encryptedKnowledgeKey);
        resultStatusObject.setKnowledgeFactorKeySaltBytes(knowledgeKeySalt);
        resultStatusObject.setPossessionFactorKeyObject(possessionKey);
        resultStatusObject.setEcDevicePublicKeyObject(ecDeviceKeyPair.getPublic());
        if (pqcDeviceKeyPair != null) {
            resultStatusObject.setPqcDevicePublicKeyObject(pqcDeviceKeyPair.getPublic());
        }
    }

}
