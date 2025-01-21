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
package com.wultra.security.powerauth.lib.cmd.header;

import com.wultra.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.TokenAndEncryptionHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;
import org.springframework.stereotype.Component;

/**
 * Factory to provide PowerAuth header supplier
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Component
public class PowerAuthHeaderFactory {

    /**
     * Creates an encryption header provider instance
     * @param model Step model
     * @param <M> Model class based on {@link EncryptionHeaderData}
     * @return New encryption header provider instance
     */
    public <M extends EncryptionHeaderData> EncryptionHeaderProvider getHeaderProvider(M model) {
        return new EncryptionHeaderProvider();
    }

    /**
     * Creates a signature header provider instance
     * @param model Step model
     * @param <M> Model class based on {@link SignatureHeaderData}
     * @return New signature header provider instance
     */
    public <M extends SignatureHeaderData> SignatureHeaderProvider getHeaderProvider(M model) {
        return new SignatureHeaderProvider();
    }

    /**
     * Creates a token header provider instance
     * @param model Step model
     * @param <M> Model class based on {@link TokenHeaderData}
     * @return New token header provider instance
     */
    public <M extends TokenHeaderData> TokenHeaderProvider getHeaderProvider(M model) {
        return new TokenHeaderProvider();
    }

    /**
     * Creates a token and encryption header provider instance
     * @param model Step model
     * @param <M> Model class based on {@link TokenAndEncryptionHeaderData}
     * @return New token and encryption header provider instance
     */
    public <M extends TokenAndEncryptionHeaderData> TokenAndEncryptionHeaderProvider getHeaderProvider(M model) {
        return new TokenAndEncryptionHeaderProvider();
    }

}
