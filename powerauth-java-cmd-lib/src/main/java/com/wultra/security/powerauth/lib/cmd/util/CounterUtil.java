/*
 * PowerAuth Command-line utility
 * Copyright 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.lib.cmd.util;

import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import org.springframework.util.Assert;

import java.nio.ByteBuffer;
import java.util.Base64;

/**
 * Helper class for counter.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class CounterUtil {

    /**
     * Get counter data. In activation version 2, numeric counter is converted to counter data. In version 3 the
     * counter data is available in model.
     *
     * <p>Keeps backward compatibility with former approaches</p>
     *
     * @param model Step model.
     * @param stepLogger Step logger.
     * @return Counter data.
     */
    public static byte[] getCtrData(BaseStepModel model, StepLogger stepLogger) {
        return getCtrData(model.getResultStatus(), stepLogger);
    }

    /**
     * Get counter data. In activation version 2, numeric counter is converted to counter data. In version 3 the
     * counter data is available in model.
     * @param resultStatusObject Activation status object.
     * @param stepLogger Step logger.
     * @return Counter data.
     */
    public static byte[] getCtrData(ResultStatusObject resultStatusObject, StepLogger stepLogger) {
        byte[] ctrData = new byte[16];
        long counter = resultStatusObject.getCounter();
        int version = resultStatusObject.getVersion().intValue();
        switch (version) {
            case 2 -> ctrData = ByteBuffer.allocate(16).putLong(8, counter).array();
            case 3 -> {
                String ctrDataBase64 = resultStatusObject.getCtrData();
                if (!ctrDataBase64.isEmpty()) {
                    ctrData = Base64.getDecoder().decode(ctrDataBase64);
                }
            }
            default -> {
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "generic-error-version",
                            "Unsupported version",
                            "The version you specified is not supported",
                            "ERROR",
                            null
                    );
                }
            }
        }
        return ctrData;
    }

    /**
     * Increment counter value in step model.
     *
     * @param model Step model.
     */
    @SuppressWarnings("unchecked")
    public static void incrementCounter(BaseStepData model) {
        // Increment the numeric counter
        ResultStatusObject resultStatusObject = model.getResultStatus();

        Long counter = resultStatusObject.getCounter();
        counter += 1;
        resultStatusObject.setCounter(counter);

        // Increment the hash based counter in case activation version is 3.
        int version = resultStatusObject.getVersion().intValue();
        if (version == 3) {
            String ctrDataBase64 = resultStatusObject.getCtrData();
            if (!ctrDataBase64.isEmpty()) {
                final byte[] ctrData = Base64.getDecoder().decode(ctrDataBase64);
                final byte[] nextCrtData = new HashBasedCounter().next(ctrData);
                Assert.state(nextCrtData != null, "nextCrtData must not be null");
                resultStatusObject.setCtrData(Base64.getEncoder().encodeToString(nextCrtData));
            }
        }
    }

}
