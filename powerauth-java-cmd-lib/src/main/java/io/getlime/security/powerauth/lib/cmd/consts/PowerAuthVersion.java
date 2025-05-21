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

import java.util.Arrays;
import java.util.List;

/**
 * PowerAuth protocol version enumeration
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public enum PowerAuthVersion {

    /**
     * Version 3.0
     */
    V3_0(3, "3.0"),

    /**
     * Version 3.1
     */
    V3_1(3, "3.1"),

    /**
     * Version 3.2
     */
    V3_2(3, "3.2"),

    /**
     * Version 3.3
     */
    V3_3(3, "3.3");

    /**
     * All supported versions
     */
    public static final List<PowerAuthVersion> ALL_VERSIONS = List.of(values());

    /**
     * Default version
     */
    public static final PowerAuthVersion DEFAULT = V3_3;

    /**
     * All versions belonging to major version 3
     */
    public static final List<PowerAuthVersion> VERSION_3 = List.of(V3_0, V3_1, V3_2, V3_3);

    /**
     * Major version value
     */
    private final int majorVersion;

    /**
     * Version string value ("3.0", "3.1", "3.2", "3.3", ...)
     */
    private final String value;

    /**
     * Constructor
     *
     * @param majorVersion Major version value
     * @param versionValue Version string value
     */
    PowerAuthVersion(int majorVersion, String versionValue) {
        this.majorVersion = majorVersion;
        this.value = versionValue;
    }

    /**
     * Provides flag whether encryption uses non-zero initialization vector
     * <p>This feature is supported only for protocol V3.1+.</p>
     *
     * @return Flag whether encryption uses non-zero initialization vector
     */
    public boolean useIv() {
        return majorVersion >= 3 && !V3_0.equals(this);
    }

    /**
     * Provides flag whether decryption uses different non-zero initialization vector.
     * <p>This feature is supported only for protocol V3.2+.</p>
     *
     * @return Flag whether decryption uses different non-zero initialization vector.
     */
    public boolean useDifferentIvForResponse() {
        return majorVersion >= 3 && !V3_0.equals(this) && !V3_1.equals(this);
    }

    /**
     * Provides flag whether encryption uses timestamp.
     * <p>This feature is supported only for protocol V3.2+.</p>
     *
     * @return Flag whether encryption uses timestamp
     */
    public boolean useTimestamp() {
        return majorVersion >= 3 && !V3_0.equals(this) && !V3_1.equals(this);
    }

    /**
     * Provides flag whether encryption uses temporary keys.
     * <p>This feature is supported only for protocol V3.3.+</p>
     *
     * @return Flag whether encryption uses temporary keys
     */
    public boolean useTemporaryKeys() {
        return majorVersion >= 3 && !V3_0.equals(this) && !V3_1.equals(this) && !V3_2.equals(this);
    }

    /**
     * @return Version string value
     */
    public String value() {
        return value;
    }

    /**
     * Detects a PowerAuth version from a provided value
     *
     * @param value Value to detect the version from
     *
     * @return PowerAuth version enum value matching the provided value
     * @throws IllegalStateException When the value is not recognized as a PowerAuth version
     */
    public static PowerAuthVersion fromValue(String value) {
        return Arrays.stream(PowerAuthVersion.values())
                .filter(version -> version.value.equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Unsupported PowerAuth version: " + value));
    }

}
