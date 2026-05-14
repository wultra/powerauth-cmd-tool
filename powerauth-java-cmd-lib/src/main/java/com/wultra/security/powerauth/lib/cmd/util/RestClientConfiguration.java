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

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * REST client configuration class.
 *
 * @author Petr Dvorak
 *
 */
public class RestClientConfiguration {

    private static final ObjectMapper mapper;

    static {
        mapper = JsonMapper.builder()
                .enable(DeserializationFeature.USE_LONG_FOR_INTS)
                .changeDefaultPropertyInclusion(incl ->
                        incl.withValueInclusion(JsonInclude.Include.NON_NULL)
                )
                .build();
    }

    /**
     * Return the mapper with default configuration.
     * @return ObjectMapper instance.
     */
    public static ObjectMapper defaultMapper() {
        return mapper;
    }

}
