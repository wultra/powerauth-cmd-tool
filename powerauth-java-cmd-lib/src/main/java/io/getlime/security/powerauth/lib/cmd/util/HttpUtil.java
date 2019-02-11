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

import com.mashape.unirest.http.Headers;

import java.util.HashMap;
import java.util.Map;

/**
 * Simple HTTP utilities class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class HttpUtil {

    /**
     * Take HTTP headers and convert list in value to string by taking the first value from the list.
     * @param headers Headers to be flattened.
     * @return Map(String,String) of flattened HTTP headers.
     */
    public static Map<String, String> flattenHttpHeaders(Headers headers) {
        Map<String, String> result = new HashMap<>();
        for (String key : headers.keySet()) {
            String value = headers.getFirst(key);
            result.put(key, value);
        }
        return result;
    }

}
