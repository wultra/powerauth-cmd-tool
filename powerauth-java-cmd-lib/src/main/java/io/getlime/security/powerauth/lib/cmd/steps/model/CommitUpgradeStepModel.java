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
package io.getlime.security.powerauth.lib.cmd.steps.model;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;

import java.util.Map;

/**
 * Model representing step for committing upgrade between different PowerAuth protocol versions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class CommitUpgradeStepModel extends BaseStepModel
        implements ResultStatusChangeable, SignatureHeaderData {

    private String statusFileName;
    private String applicationKey;
    private String applicationSecret;

    /**
     * Set file name of the file with stored activation status.
     *
     * @param statusFileName Status file name.
     */
    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    /**
     * Set application key.
     *
     * @param applicationKey Application key.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Set application secret.
     *
     * @param applicationSecret Application secret.
     */
    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    /**
     * Get status file name.
     *
     * @return Status file name.
     */
    public String getStatusFileName() {
        return statusFileName;
    }

    /**
     * Get application key.
     *
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Get application secret.
     *
     * @return Application secret.
     */
    public String getApplicationSecret() {
        return applicationSecret;
    }

    @Override
    public PowerAuthSignatureTypes getSignatureType() {
        return PowerAuthSignatureTypes.POSSESSION;
    }

    @Override
    public String getPassword() {
        // TODO no value here?
        return null;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
    }

}
