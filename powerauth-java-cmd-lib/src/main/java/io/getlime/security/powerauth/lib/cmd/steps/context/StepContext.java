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
package io.getlime.security.powerauth.lib.cmd.steps.context;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import lombok.Data;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

/**
 * Step call context
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data
public class StepContext<M extends BaseStepData, R> {

    /**
     * Additional context attributes
     */
    private Map<String, Object> attributes = new HashMap<>();

    /**
     * Data model
     */
    private M model;

    /**
     * Request context
     */
    private RequestContext requestContext;

    /**
     * Response context
     */
    private ResponseContext<R> responseContext;

    /**
     * Current step identification
     */
    private PowerAuthStep step;

    // TODO consider separation to two security contexts
    private EciesEncryptor encryptor;

    private EciesEncryptor eciesEncryptorL1;

    private EciesEncryptor eciesEncryptorL2;

    private KeyPair deviceKeyPair;

}
