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

import org.json.simple.JSONObject;

/**
 * Helper class for obtaining typed values from JSON.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class JsonUtil {

    /**
     * Extract long value from JSON object stored using key with given key. In case the deserialized value type
     * is not numeric, value 0 is returned.
     * @param o JSON object.
     * @param key Key name.
     * @return Extracted long value.
     */
    public static long longValue(JSONObject o, String key) {
        return safeLong(o.get(key));
    }

    /**
     * Extract int value from JSON object stored using key with given key. In case the deserialized value type
     * is not numeric, value 0 is returned.
     * @param o JSON object.
     * @param key Key name.
     * @return Extracted int value.
     */
    public static int intValue(JSONObject o, String key) {
        return (int) safeLong(o.get(key));
    }

    /**
     * Extract String value from JSON object stored using key with given name. In case the deserialized value type
     * is not of String type, value "" is returned.
     * @param o JSON object.
     * @param key Key name.
     * @return Extracted String value.
     */
    public static String stringValue(JSONObject o, String key) {
        return safeString(o.get(key));
    }

    /**
     * Convert Object which is expected to contain long value to long.
     * @param o Object with expected long value.
     * @return The long value.
     */
    private static long safeLong(Object o) {
        return o instanceof Long ? (long) o : 0;
    }

    /**
     * Convert Object which is expected to contain String value to String.
     * @param o Object with expected String value.
     * @return The String value.
     */
    private static String safeString(Object o) {
        return o instanceof String ? (String) o : "";
    }

}
