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
package com.wultra.security.powerauth.app.cmd;

import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test command-line client implementation.
 * 
 * @author Petr Dvorak
 *
 */
public class ApplicationTest {

	/**
	 * Register crypto providers.
	 */
	@BeforeAll
	public static void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test encryption of the KEY_KNOWLEDGE_FACTOR using the password.
	 * @throws Exception In case test fails.
	 */
	@Test
	public void testPasswordEncryption() throws Exception {

		for (int i = 0; i < 20; i++) {
			KeyPair kpd = new KeyGenerator().generateKeyPair();
			KeyPair kps = new KeyGenerator().generateKeyPair();
			SecretKey secret = new KeyGenerator().computeSharedKey(kpd.getPrivate(), kps.getPublic());

			SecretKey knowledgeSecret = new PowerAuthClientKeyFactory().generateClientKnowledgeFactorKey(secret);
			byte[] salt = new KeyGenerator().generateRandomBytes(16);

			byte[] encrypted = EncryptedStorageUtil.storeKnowledgeFactorKey("1234".toCharArray(), knowledgeSecret, salt, new KeyGenerator());

			// Correct password
			SecretKey knowledgeSecret2 = EncryptedStorageUtil.getKnowledgeFactorKey("1234".toCharArray(), encrypted, salt, new KeyGenerator());
			assertEquals(knowledgeSecret, knowledgeSecret2);

			// Incorrect passwords
			SecretKey knowledgeSecret3 = EncryptedStorageUtil.getKnowledgeFactorKey("22".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = EncryptedStorageUtil.getKnowledgeFactorKey(" ".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = EncryptedStorageUtil.getKnowledgeFactorKey("X123456".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = EncryptedStorageUtil.getKnowledgeFactorKey("TestLongPasswordMore-Than 16BytesJustInCase".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
		}

	}

}
