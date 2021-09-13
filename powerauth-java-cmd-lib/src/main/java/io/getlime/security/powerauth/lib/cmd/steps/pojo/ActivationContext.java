/*
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
package io.getlime.security.powerauth.lib.cmd.steps.pojo;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import lombok.Builder;
import lombok.Data;

import java.security.KeyPair;

/**
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data @Builder
public class ActivationContext {

    private CreateActivationStepModel modelCreate;

    private PrepareActivationStepModel modelPrepare;

    private KeyPair deviceKeyPair;

    private EciesEncryptor eciesEncryptorL1;

    private EciesEncryptor eciesEncryptorL2;

    private ResultStatusObject resultStatusObject;

    private String password;

    private StepLogger stepLogger;

}
