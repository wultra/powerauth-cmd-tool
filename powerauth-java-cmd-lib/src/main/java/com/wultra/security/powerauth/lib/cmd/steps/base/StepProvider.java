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
package com.wultra.security.powerauth.lib.cmd.steps.base;

import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.exception.PowerAuthCmdException;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Provider of PowerAuth step process components
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Component
public class StepProvider {

    /**
     * Step logger
     */
    private final StepLogger stepLogger;

    /**
     * Mapping of a PowerAuthStep enumeration to a corresponding version of process component
     */
    private Map<PowerAuthStep, Map<PowerAuthVersion, BaseStep>> mappingStepVersion = Collections.emptyMap();

    /**
     * Constructor
     *
     * @param stepList All existing PowerAuth step components
     * @param stepLogger Step logger
     */
    @Autowired
    public StepProvider(
            List<BaseStep> stepList,
            StepLogger stepLogger) {
        this.stepLogger = stepLogger;

        registerPowerAuthSteps(stepList);
    }

    private void registerPowerAuthSteps(List<BaseStep> steps) {
        final Map<PowerAuthStep, Map<PowerAuthVersion, BaseStep>> mappingStepVersion = new HashMap<>();

        steps.forEach(step -> {
            final Map<PowerAuthVersion, BaseStep> mappingVersion =
                    mappingStepVersion.computeIfAbsent(step.getStep(), value -> new HashMap<>());

            step.getSupportedVersions().forEach(supportedVersion ->
                    mappingVersion.put(supportedVersion, step));
        });

        this.mappingStepVersion = mappingStepVersion;
    }

    /**
     * Provides information about existence of PowerAuth step process components
     * @param step PowerAuth step identification
     * @return true when there is a component for the specified PowerAuth step, false otherwise
     */
    public boolean exists(PowerAuthStep step) {
        return mappingStepVersion.containsKey(step);
    }

    /**
     * Provides step process component by PowerAuth step identification and version
     *
     * @param step PowerAuth step identification
     * @param version PowerAuth version
     * @return Step process component corresponding to the specified PowerAuth step, version combination
     * @throws PowerAuthCmdException when there is no such component for the provided PowerAuth step
     */
    public BaseStep getStep(PowerAuthStep step, PowerAuthVersion version) throws PowerAuthCmdException {
        return Optional.ofNullable(
                mappingStepVersion.get(step).get(version)
        ).orElseThrow(() -> {
            stepLogger.writeItem(
                    "generic-error-version",
                    "Unsupported version",
                    "The version you specified is not supported: " + version,
                    "ERROR",
                    null
            );
            return new PowerAuthCmdException();
        });
    }

    /**
     * Provides available PowerAuth steps for the specified PowerAuthVersion
     * @param version PowerAuthVersion value
     * @return Supported versions
     */
    public Set<PowerAuthStep> getAvailableSteps(PowerAuthVersion version) {
        final Set<PowerAuthStep> steps = new HashSet<>();
        for (PowerAuthStep step : mappingStepVersion.keySet()) {
            if (mappingStepVersion.get(step).containsKey(version)) {
                steps.add(step);
            }
        }
        return steps;
    }

    /**
     * Provides supported versions for the specified PowerAuth step
     * @param step PowerAuth step identification
     * @return Supported versions
     */
    public Set<PowerAuthVersion> getSupportedVersions(PowerAuthStep step) {
        return Optional.ofNullable(mappingStepVersion.get(step))
                .orElse(Collections.emptyMap())
                .keySet()
                .stream()
                .sorted()
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

}
