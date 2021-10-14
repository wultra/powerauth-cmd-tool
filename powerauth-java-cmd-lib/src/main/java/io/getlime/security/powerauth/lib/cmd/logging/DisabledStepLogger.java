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
package io.getlime.security.powerauth.lib.cmd.logging;

import java.util.Map;

/**
 * Disabled step logger for silent logging
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class DisabledStepLogger implements StepLogger {

    public static final StepLogger INSTANCE = new DisabledStepLogger();

    private DisabledStepLogger() {

    }

    @Override
    public void start() { }

    @Override
    public void writeItem(String id, String name, String description, String status, Object object) { }

    @Override
    public void writeServerCall(String id, String uri, String method, Object requestObject, byte[] requestBytes, Map<String, ?> headers) { }

    @Override
    public void writeServerCallOK(String id, Object responseObject, Map<String, ?> headers) { }

    @Override
    public void writeServerCallError(String id, int statusCode, Object responseObject, Map<String, ?> headers) { }

    @Override
    public void close() { }

    @Override
    public void writeServerCallConnectionError(String id, Exception e) { }

    @Override
    public void writeError(String id, String errorMessage) { }

    @Override
    public void writeError(String id, Exception exception) { }

    @Override
    public void writeError(String id, String name, String errorMessage) { }

    @Override
    public void writeError(String id, String name, String errorMessage, Exception exception) { }

    @Override
    public void writeDoneOK(String id) { }

    @Override
    public void writeDoneFailed(String id) { }

}
