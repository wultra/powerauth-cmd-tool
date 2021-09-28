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
package io.getlime.security.powerauth.lib.cmd.header;

import io.getlime.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;
import org.springframework.stereotype.Component;

/**
 * Factory to provide PowerAuth header supplier
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Component
public class PowerAuthHeaderFactory {

    public <M extends EncryptionHeaderData> EncryptionHeaderProvider getHeaderProvider(M model) {
        return new EncryptionHeaderProvider();
    }

    public <M extends SignatureHeaderData> SignatureHeaderProvider getHeaderProvider(M model) {
        return new SignatureHeaderProvider();
    }

    public <M extends TokenHeaderData> TokenHeaderProvider getHeaderProvider(M model) {
        return new TokenHeaderProvider();
    }

}
