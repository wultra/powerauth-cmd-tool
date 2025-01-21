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
package com.wultra.security.powerauth.lib.cmd.consts;

import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.springframework.core.ParameterizedTypeReference;

import java.nio.charset.StandardCharsets;

/**
 * Global PowerAuth constants
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class PowerAuthConst {

    /**
     * Empty json bytes
     */
    public static final byte[] EMPTY_JSON_BYTES = "{}".getBytes(StandardCharsets.UTF_8);

    /**
     * Most common response type reference for version 3
     */
    public static final ParameterizedTypeReference<EciesEncryptedResponse> RESPONSE_TYPE_REFERENCE_V3 = new ParameterizedTypeReference<>() {};

}
