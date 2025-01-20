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
package com.wultra.security.powerauth.lib.cmd.steps.model;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Model representing parameters of the step for verifying data signature.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class VerifySignatureStepModel extends BaseStepModel
        implements ResultStatusChangeable, DryRunCapable, SignatureHeaderData {

    private static final Logger logger = LoggerFactory.getLogger(VerifySignatureStepModel.class);

    /**
     * File name of the file with stored activation status.
     */
    private String statusFileName;

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Application secret.
     */
    private String applicationSecret;

    /**
     * HTTP method used for the request call.
     */
    private String httpMethod;

    /**
     * Resource identifier for a given call.
     */
    private String resourceId;

    /**
     * PowerAuth signature type.
     */
    private PowerAuthSignatureTypes signatureType;

    /**
     * The request data, used for POST, PUT and DELETE methods.
     */
    private byte[] data;

    /**
     * Password for the password related key encryption.
     */
    private String password;

    /**
     * flag indicating that this step should be terminated before the networking call.
     */
    private boolean dryRun;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("HTTP_METHOD", httpMethod);
        context.put("RESOURCE_ID", resourceId);
        context.put("SIGNATURE_TYPE", signatureType.toString());
        context.put("DATA", data);
        context.put("PASSWORD", password);
        context.put("DRY_RUN", dryRun);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setHttpMethod((String) context.get("HTTP_METHOD"));
        if ((context.containsKey("ENDPOINT") && context.get("ENDPOINT") != null) &&
            (!context.containsKey("RESOURCE_ID") || context.get("RESOURCE_ID") == null)) {
            logger.warn("Usage of deprecated 'ENDPOINT' key in the context map of VerifySignatureStepModel, use the 'RESOURCE_ID' key instead.");
            context.put("RESOURCE_ID", context.get("ENDPOINT"));
        }
        setResourceId((String) context.get("RESOURCE_ID"));
        setSignatureType(PowerAuthSignatureTypes.getEnumFromString((String) context.get("SIGNATURE_TYPE")));
        setData((byte[]) context.get("DATA"));
        setPassword((String) context.get("PASSWORD"));
        setDryRun((boolean) context.get("DRY_RUN"));
    }

}
