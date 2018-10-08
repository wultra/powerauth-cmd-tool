/*
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
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
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
     * Get counter data. In version 2.0 and 2.1, numeric counter is converted to counter data. In version 3.0 the
     * counter data is available in model.
     * @param model Step model.
     * @param stepLogger Step logger.
     * @return Counter data.
     */
    public static byte[] getCtrData(BaseStepModel model, JsonStepLogger stepLogger) {
        byte[] ctrData = new byte[16];
        long counter = (long) model.getResultStatusObject().get("counter");
        switch (model.getVersion()) {
            case "2.0":
            case "2.1":
                ctrData = ByteBuffer.allocate(16).putLong(8, counter).array();
                break;
            case "3.0":
                ctrData = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("ctrData"));
                break;
            default:
                stepLogger.writeItem(
                        "Unsupported version",
                        "The version you specified is not supported",
                        "ERROR",
                        null
                );
        }
        return ctrData;
    }

    /**
     * Increment counter value in step model. In version 2.0 and 2.1 only numeric counter is incremented. In version
     * 3.0 the counter data is incremented using hash based counter, too.
     *
     * @param model Step model.
     */
    public static void incrementCounter(BaseStepModel model) {
        // Increment the counter
        long counter = (long) model.getResultStatusObject().get("counter");
        byte[] ctrData = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("ctrData"));
        counter += 1;
        model.getResultStatusObject().put("counter", counter);
        if ("3.0".equals(model.getVersion())) {
            ctrData = new HashBasedCounter().next(ctrData);
            model.getResultStatusObject().put("ctrData", BaseEncoding.base64().encode(ctrData));
        }
    }

}
