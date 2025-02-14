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

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.annotation.Nullable;
import org.springframework.http.HttpHeaders;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Simple HTTP utilities class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class HttpUtil {

    /**
     * Flattens headers to a simple map of header names to first header value for a given name
     * @param headers HTTP headers
     * @return Headers as a map of header names to first header value for a given name
     */
    public static Map<String, String> flattenHttpHeaders(HttpHeaders headers) {
        Map<String, String> result = new HashMap<>();
        if (headers != null) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                result.put(entry.getKey(), headers.getFirst(entry.getKey()));
            }
        }
        return result;
    }

    /**
     * Serializes an object value for request sending as byte array representation
     * @param objectValue Object value
     * @return byte array representing the object value
     * @throws JsonProcessingException when an error during serialization to JSON occurred
     */
    public static byte[] toRequestBytes(@Nullable Object objectValue) throws JsonProcessingException {
        byte[] requestBytes;
        if (objectValue == null) {
            requestBytes = null;
        } else if (objectValue instanceof byte[]) {
            requestBytes = (byte[]) objectValue;
        } else {
            requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(objectValue);
        }
        return requestBytes;
    }

    /**
     * Deserializes an object entity from byte array representation of a json
     * @param data Byte array representation of json
     * @param cls Class
     * @param <T> Type of the deserialized object
     * @return Object entity
     * @throws IOException when an error during deserialization from JSON occurred
     */
    public static <T> T fromBytes(byte[] data, Class<T> cls) throws IOException {
        return RestClientConfiguration.defaultMapper().readValue(data, cls);
    }

}
