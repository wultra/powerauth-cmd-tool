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
package io.getlime.security.powerauth.lib.cmd.steps.model.data;

import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;

import java.security.PublicKey;
import java.util.Map;

/**
 * Data used in activation steps
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public interface ActivationData extends ResultStatusChangeable, BaseStepData {

    /**
     * @return Activation name.
     */
    String getActivationName();

    /**
     * @return Application secret.
     */
    String getApplicationSecret();

    /**
     * @return Custom attributes.
     */
    Map<String, Object> getCustomAttributes();

    /**
     * @return Information about user device.
     */
    String getDeviceInfo();

    /**
     * @return Identity attributes.
     */
    Map<String, String> getIdentityAttributes();

    /**
     * @return Base64 encoded master public key.
     */
    PublicKey getMasterPublicKey();

    /**
     * @return Knowledge key password.
     */
    String getPassword();

    /**
     * @return User device platform.
     */
    String getPlatform();

}
