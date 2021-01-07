/*
 * PowerAuth Command-line utility
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
package io.getlime.security.powerauth.lib.cmd.util;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.Map;

/**
 * Map utilities.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MapUtil {

    public static <K, V> MultiValueMap<K, V> toMultiValueMap(Map<K, V> map) {
        MultiValueMap<K, V> resultMap = new LinkedMultiValueMap<>();
        for (Map.Entry<K, V> entry: map.entrySet()) {
            resultMap.put(entry.getKey(), Collections.singletonList(entry.getValue()));
        }
        return resultMap;
    }
}
