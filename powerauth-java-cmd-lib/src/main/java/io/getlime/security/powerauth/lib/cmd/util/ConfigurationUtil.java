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

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
import org.json.simple.JSONObject;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Helper class for configuration 
 *
 * @author Petr Dvorak
 *
 */
public class ConfigurationUtil {

    private static final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Get application key value that is set in dictionary, or a default value.
     * @param clientConfigObject Object with configuration.
     * @return Application key.
     */
    public static String getApplicationKey(JSONObject clientConfigObject) {
        if (clientConfigObject.get("applicationKey") != null) {
            return (String) clientConfigObject.get("applicationKey");
        }
        return null;
    }

    /**
     * Get application secret that is set in dictionary, or a default value.
     * @param clientConfigObject Object with configuration.
     * @return Application secret.
     */
    public static String getApplicationSecret(JSONObject clientConfigObject) {
        if (clientConfigObject.get("applicationSecret") != null) {
            return (String) clientConfigObject.get("applicationSecret");
        }
        return null;
    }

    /**
     * Get application name that is set in dictionary, or a default value.
     * @param clientConfigObject Object with configuration.
     * @return Application name.
     */
    public static String getApplicationName(JSONObject clientConfigObject) {
        if (clientConfigObject.get("applicationName") != null) {
            return (String) clientConfigObject.get("applicationName");
        }
        return null;
    }

    /**
     * Get master public key from the configuration object
     * @param clientConfigObject Object with configuration.
     * @param stepLogger Step logger instance.
     * @return Master public key.
     */
    public static PublicKey getMasterKey(JSONObject clientConfigObject, JsonStepLogger stepLogger) {
        if (clientConfigObject != null && clientConfigObject.get("masterPublicKey") != null) {
            try {
                byte[] masterKeyBytes = BaseEncoding.base64().decode((String) clientConfigObject.get("masterPublicKey"));
                return keyConvertor.convertBytesToPublicKey(masterKeyBytes);
            } catch (IllegalArgumentException e) {
                stepLogger.writeError("master-key-error-encoding", "Invalid Master Server Public Key", "Master Server Public Key must be stored in a valid Base64 encoding", e);
                stepLogger.writeDoneFailed("master-key-failed");
                System.exit(1);
            } catch (InvalidKeySpecException e) {
                stepLogger.writeError("master-key-error-format", "Invalid Master Server Public Key", "Master Server Public Key was stored in an incorrect format", e);
                stepLogger.writeDoneFailed("master-key-failed");
                System.exit(1);
            } catch (CryptoProviderException e) {
                stepLogger.writeError("master-key-error-cryptography", "Cryptography Provider Error", "Cryptography provider is initialized incorrectly", e);
                stepLogger.writeDoneFailed("master-key-failed");
                System.exit(1);
            }
        } else {
            stepLogger.writeError("master-key-error-public-key-missing", "Invalid Master Server Public Key", "Master Server Public Key not found in the config file");
            stepLogger.writeDoneFailed("master-key-failed");
            System.exit(1);
        }
        return null;
    }

}
