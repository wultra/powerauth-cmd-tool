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

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * PowerAuth step enumeration
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public enum PowerAuthStep {

    /**
     * Creation of new activation
     */
    ACTIVATION_CREATE_CUSTOM("activation-create-custom", "Activation With Custom Attributes", "create-custom"),

    /**
     * Creation of new activation using custom identity attributes
     */
    ACTIVATION_CREATE("activation-create", "Activation", "create"),

    /**
     * Former creation of new activation
     */
    @Deprecated
    ACTIVATION_PREPARE("activation-prepare", "Activation", "prepare"),

    /**
     * Removal of an existing activation
     */
    ACTIVATION_REMOVE("activation-remove", "Activation Removal", "remove"),

    /**
     * Recovering an activation
     */
    ACTIVATION_RECOVERY("activation-recovery", "Activation With Recovery Code", "create-recovery"),

    /**
     * Status retrieval of an existing activation
     */
    ACTIVATION_STATUS("activation-status", "Activation Status Check", "status"),

    /**
     * Send and verify an encrypted request
     */
    ENCRYPT("encrypt", "Encrypt Request", "encrypt"),

    /**
     * Confirming an activation recovery
     */
    RECOVERY_CONFIRM("recovery-confirm", "Confirm Recovery Code", "confirm-recovery-code"),

    /**
     * Send and verify a signed and encrypted request
     */
    SIGN_ENCRYPT("sign-encrypt", "Sign and Encrypt Request", "sign-encrypt"),

    /**
     * Verifying a signed request
     */
    SIGNATURE_VERIFY("signature-verify", "Signature Validation", "sign"),

    /**
     * Creating new token
     */
    TOKEN_CREATE("token-create", "Token Create", "create-token"),

    /**
     * Removing a previously created token
     */
    TOKEN_REMOVE("token-remove", "Token Remove", "remove-token"),

    /**
     * Validating a previously created token
     */
    TOKEN_VALIDATE("token-validate", "Token Digest Validation", "validate-token"),

    /**
     * Committing upgrade from activation version 2 to version 3
     */
    UPGRADE_COMMIT("upgrade-commit", "Upgrade Commit", "commit-upgrade"),

    /**
     * Starting upgrade from activation version 2 to version 3
     */
    UPGRADE_START("upgrade-start", "Upgrade", "start-upgrade"),

    /**
     * Unlocking secure vault
     */
    VAULT_UNLOCK("vault-unlock", "Vault Unlock", "unlock");

    /**
     * Mapping between alias names and PowerAuth steps
     */
    private static final Map<String, PowerAuthStep> stepByAlias;

    static {
        Set<String> uniqueAliases = new HashSet<>();
        Arrays.stream(PowerAuthStep.values()).forEach(step -> {
            if (uniqueAliases.contains(step.alias)) {
                throw new IllegalStateException("Already existing step alias name: " + step.alias);
            }
            uniqueAliases.add(step.alias);
        });

        Set<String> uniqueIds = new HashSet<>();
        Arrays.stream(PowerAuthStep.values()).forEach(step -> {
            if (uniqueIds.contains(step.id)) {
               throw new IllegalStateException("Already existing step id: " + step.id);
            }
            uniqueIds.add(step.id);
        });

        stepByAlias = Arrays.stream(PowerAuthStep.values())
                .collect(Collectors.toMap(step -> step.alias, Function.identity()));
    }

    /**
     * Constructor
     *
     * @param id Unique identification of the step
     * @param description Description of the step
     * @param alias Alias name of the step
     */
    PowerAuthStep(String id, String description, String alias) {
        this.id = id;
        this.description = description;
        this.alias = alias;
    }

    /**
     * Alias name of the step
     */
    String alias;

    /**
     * Description of the step
     */
    String description;

    /**
     * Unique identification of the step
     */
    String id;

    /**
     * @return Alis of the step
     */
    public String alias() {
        return alias;
    }

    /**
     * @return Description of the step
     */
    public String description() {
        return description;
    }

    /**
     * @return Unique identification of the step
     */
    public String id() {
        return id;
    }

    /**
     * Detects a PowerAuth step from a provided value
     *
     * @param value Value to detect the step from
     *
     * @return PowerAuth step enum value matching the provided value
     * @throws IllegalStateException When the value is not recognized as a PowerAuth step
     */
    public static PowerAuthStep fromMethod(String value) {
        return Optional.ofNullable(stepByAlias.get(value))
                .orElseThrow(() -> new IllegalStateException("Unknown PowerAuth step value: " + value));
    }

}
