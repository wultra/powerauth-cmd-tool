/*
 * PowerAuth Command-line utility
 * Copyright 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.lib.cmd.steps.context.security;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.Builder;
import lombok.Data;

import java.security.KeyPair;

/**
 * Security context for activations
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data
@Builder
public class ActivationSecurityContext implements SecurityContext {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private EciesEncryptor encryptorL1;

    private EciesEncryptor encryptorL2;

    private KeyPair deviceKeyPair;

    public String getDevicePublicKeyBase64() throws CryptoProviderException {
        byte[] devicePublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        return BaseEncoding.base64().encode(devicePublicKeyBytes);
    }

}
