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
package io.getlime.security.powerauth.lib.cmd.logging.model;

/**
 * Class representing an error in step.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class StepError {

    private final String id;
    private final String name;
    private final String errorMessage;
    private final Exception exception;

    /**
     * Constructor with error details.
     *
     * @param id Error ID.
     * @param name Error name.
     * @param errorMessage Error message.
     * @param exception Exception.
     */
    public StepError(String id, String name, String errorMessage, Exception exception) {
        this.id = id;
        this.name = name;
        this.errorMessage = errorMessage;
        this.exception = exception;
    }

    /**
     * Get error ID.
     * @return Error ID.
     */
    public String getId() {
        return id;
    }

    /**
     * Get error name.
     * @return Error name.
     */
    public String getName() {
        return name;
    }

    /**
     * Get error message.
     * @return Error message.
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Get exception.
     * @return Exception.
     */
    public Exception getException() {
        return exception;
    }
}
