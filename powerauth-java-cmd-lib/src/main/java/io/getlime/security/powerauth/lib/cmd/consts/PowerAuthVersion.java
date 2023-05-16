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

import com.google.common.collect.ImmutableList;

import java.util.Arrays;

/**
 * PowerAuth protocol version enumeration
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public enum PowerAuthVersion {

    /**
     * Version 2.0
     */
    V2_0(2, "2.0"),

    /**
     * Version 2.1
     */
    V2_1(2, "2.1"),

    /**
     * Version 3.0
     */
    V3_0(3, "3.0"),

    /**
     * Version 3.1
     */
    V3_1(3, "3.1");

    /**
     * All supported versions
     */
    public static final ImmutableList<PowerAuthVersion> ALL_VERSIONS = ImmutableList.copyOf(values());

    /**
     * Default version
     */
    public static final PowerAuthVersion DEFAULT = V3_1;

    /**
     * All versions belonging to major version 2
     */
    public static final ImmutableList<PowerAuthVersion> VERSION_2 = ImmutableList.of(V2_0, V2_1);

    /**
     * All versions belonging to major version 3
     */
    public static final ImmutableList<PowerAuthVersion> VERSION_3 = ImmutableList.of(V3_0, V3_1);

    /**
     * Major version value
     */
    private final int majorVersion;

    /**
     * Version string value ("2.1", "3.0", ...)
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
