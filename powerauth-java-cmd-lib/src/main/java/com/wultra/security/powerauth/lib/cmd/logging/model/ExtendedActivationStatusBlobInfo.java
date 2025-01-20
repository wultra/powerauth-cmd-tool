/*
 * Copyright 2020 Wultra s.r.o.
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
package com.wultra.security.powerauth.lib.cmd.logging.model;

import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;

/**
 * Class that represents the contents of the activation status blob extended with
 * additional displayable attributes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ExtendedActivationStatusBlobInfo extends ActivationStatusBlobInfo {

    private String activationStatusName;

    /**
     * Creates a copy of the original ActivationStatusBlobInfo raw attributes
     * @param orig Original data
     * @return Copy of the original ActivationStatusBlobInfo raw attributes
     */
    public static ExtendedActivationStatusBlobInfo copy(ActivationStatusBlobInfo orig) {
        final ExtendedActivationStatusBlobInfo result = new ExtendedActivationStatusBlobInfo();
        result.setActivationStatus(orig.getActivationStatus());
        result.setCtrByte(orig.getCtrByte());
        result.setCtrDataHash(orig.getCtrDataHash());
        result.setCtrLookAhead(orig.getCtrLookAhead());
        result.setCurrentVersion(orig.getCurrentVersion());
        result.setFailedAttempts(orig.getFailedAttempts());
        result.setMaxFailedAttempts(orig.getMaxFailedAttempts());
        result.setUpgradeVersion(orig.getUpgradeVersion());
        result.setValid(orig.isValid());

        // Add additional extended attributes
        result.setActivationStatusName(result.convertStatusToStatusName(orig.getActivationStatus()));
        return result;
    }

    /**
     * Set a displayable value of the activation status.
     *
     * @param activationStatusName A displayable value of the activation status.
     */
    public void setActivationStatusName(String activationStatusName) {
        this.activationStatusName = activationStatusName;
    }

    /**
     * Get a displayable value of the activation status.
     *
     * @return A displayable value of the activation status.
     */
    public String getActivationStatusName() {
        return activationStatusName;
    }

    /**
     * Converts numerical status value to a comprehensive displayable value.<br/>
     * <ul>
     *     <li>1 - CREATED</li>
     *     <li>2 - PENDING_COMMIT</li>
     *     <li>3 - ACTIVE</li>
     *     <li>4 - BLOCKED</li>
     *     <li>5 - REMOVED</li>
     *     <li>other values - UNKNOWN</li>
     * </ul>
     *
     * @param status Numerical value of the status.
     * @return A comprehensive displayable value.
     */
    private String convertStatusToStatusName(byte status) {
        return switch (status) {
            case 1 -> "CREATED";
            case 2 -> "PENDING_COMMIT";
            case 3 -> "ACTIVE";
            case 4 -> "BLOCKED";
            case 5 -> "REMOVED";
            default -> "UNKNOWN";
        };
    }
}
