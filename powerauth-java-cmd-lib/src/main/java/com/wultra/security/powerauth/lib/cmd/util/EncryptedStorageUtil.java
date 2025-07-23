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
package com.wultra.security.powerauth.lib.cmd.util;

import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;

/**
 * Utility class implementing processes related to data storage on client side.
 *
 * @author Petr Dvorak
 *
 */
public class EncryptedStorageUtil {

    private static final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Encrypt the KEY_KNOWLEDGE_FACTOR key using a provided password.
     * @param password Password to be used for encryption.
     * @param knowledgeFactorSecretKey Original KEY_KNOWLEDGE_FACTOR key.
     * @param salt Random salt.
     * @param keyGenerator Key generator instance.
     * @return Encrypted KEY_KNOWLEDGE_FACTOR using password and random salt.
     * @throws InvalidKeyException In case invalid key is provided.
     * @throws CryptoProviderException In case cryptography provider is initialized incorrectly.
     * @throws GenericCryptoException In case any other cryptography error occurs.
     */
    public static byte[] storeKnowledgeFactorKey(char[] password, SecretKey knowledgeFactorSecretKey, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Ask for the password and generate storage key
        SecretKey encryptionKnowledgeFactorKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

        // Encrypt the knowledge related key using the password derived key
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] knowledgeFactorSecretKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(knowledgeFactorSecretKey);
        // TODO - empty IV is an antipattern for AES/CBC, improve for crypto4, reconsider PBKDF algorithm as well
        byte[] iv = new byte[16];
        return aes.encrypt(knowledgeFactorSecretKeyBytes, iv, encryptionKnowledgeFactorKey, "AES/CBC/NoPadding");
    }

    /**
     * Decrypt the KEY_KNOWLEDGE_FACTOR key using a provided password.
     * @param password Password to be used for decryption.
     * @param cKnowledgeFactorSecretKeyBytes Encrypted KEY_KNOWLEDGE_FACTOR key.
     * @param salt Salt that was used for encryption.
     * @param keyGenerator Key generator instance.
     * @return Original KEY_KNOWLEDGE_FACTOR key.
     * @throws InvalidKeyException In case invalid key is provided.
     * @throws CryptoProviderException In case cryptography provider is initialized incorrectly.
     * @throws GenericCryptoException In case any other cryptography error occurs.
     */
    public static SecretKey getKnowledgeFactorKey(char[] password, byte[] cKnowledgeFactorSecretKeyBytes, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Ask for the password and generate storage key
        SecretKey encryptionKnowledgeFactorKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

        // Encrypt the knowledge related key using the password derived key
        AESEncryptionUtils aes = new AESEncryptionUtils();
        // TODO - empty IV is an antipattern for AES/CBC, improve for crypto4, reconsider PBKDF algorithm as well
        byte[] iv = new byte[16];
        byte[] knowledgeFactorSecretKeyBytes = aes.decrypt(cKnowledgeFactorSecretKeyBytes, iv, encryptionKnowledgeFactorKey, "AES/CBC/NoPadding");
        return keyConvertor.convertBytesToSharedSecretKey(knowledgeFactorSecretKeyBytes);
    }

}
