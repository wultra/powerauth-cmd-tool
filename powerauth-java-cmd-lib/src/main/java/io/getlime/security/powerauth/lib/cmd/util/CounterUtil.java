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
package io.getlime.security.powerauth.lib.cmd.util;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.BaseStepModel;

import java.nio.ByteBuffer;

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
     * @param model Step model.
     * @param stepLogger Step logger.
     * @return Counter data.
     */
    public static byte[] getCtrData(BaseStepModel model, StepLogger stepLogger) {
        byte[] ctrData = new byte[16];
        long counter = JsonUtil.longValue(model.getResultStatusObject(), "counter");
        int version = JsonUtil.intValue(model.getResultStatusObject(), "version");
        switch (version) {
            case 2:
                ctrData = ByteBuffer.allocate(16).putLong(8, counter).array();
                break;
            case 3:
                String ctrDataBase64 = JsonUtil.stringValue(model.getResultStatusObject(), "ctrData");
                if (!ctrDataBase64.isEmpty()) {
                    ctrData = BaseEncoding.base64().decode(ctrDataBase64);
                }
                break;
            default:
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
        return ctrData;
    }

    /**
     * Increment counter value in step model. In version 2.0 and 2.1 only numeric counter is incremented. In version
     * 3.0 the counter data is incremented using hash based counter, too.
     *
     * @param model Step model.
     */
    @SuppressWarnings("unchecked")
    public static void incrementCounter(BaseStepModel model) {
        // Increment the numeric counter
        long counter = JsonUtil.longValue(model.getResultStatusObject(), "counter");
        counter += 1;
        model.getResultStatusObject().put("counter", counter);

        // Increment the hash based counter in case activation version is 3.
        int version = JsonUtil.intValue(model.getResultStatusObject(), "version");
        if (version == 3) {
            String ctrDataBase64 = JsonUtil.stringValue(model.getResultStatusObject(), "ctrData");
            if (!ctrDataBase64.isEmpty()) {
                byte[] ctrData = BaseEncoding.base64().decode(ctrDataBase64);
                ctrData = new HashBasedCounter().next(ctrData);
                model.getResultStatusObject().put("ctrData", BaseEncoding.base64().encode(ctrData));
            }
        }
    }

}
