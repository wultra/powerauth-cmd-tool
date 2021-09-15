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
package io.getlime.security.powerauth.lib.cmd.consts;

/**
 * Step logger type enumeration
 * <p>
 *     Determines format type of logged messages
 * </p>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public enum StepLoggerType {

    /**
     * Disabled logging of step messages
     */
    DISABLED,

    /**
     * Json format of step messages
     */
    JSON,

    /**
     * Simple object format of step messages
     */
    OBJECT

}
