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
 * Class representing a generic item in step.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class StepItem {

    private final String name;
    private final String description;
    private final String status;
    private final Object object;

    /**
     * Constructor with all details.
     *
     * @param name Item name.
     * @param description Item description.
     * @param status Status.
     * @param object Related object (optional).
     */
    public StepItem(String name, String description, String status, Object object) {
        this.name = name;
        this.description = description;
        this.status = status;
        this.object = object;
    }

    /**
     * Get item name.
     * @return Item name.
     */
    public String getName() {
        return name;
    }

    /**
     * Get item description.
     * @return Item description.
     */
    public String getDescription() {
        return description;
    }

    /**
     * Get item status.
     * @return Item status.
     */
    public String getStatus() {
        return status;
    }

    /**
     * Get related object (optional).
     * @return Related object (optional).
     */
    public Object getObject() {
        return object;
    }
}
