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

import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.util.config.SdkConfiguration;
import org.json.simple.JSONObject;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

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
    public static PublicKey getMasterPublicKey(JSONObject clientConfigObject, StepLogger stepLogger) {
        if (clientConfigObject != null && clientConfigObject.get("masterPublicKey") != null) {
            return convertMasterPublicKey((String) clientConfigObject.get("masterPublicKey"), stepLogger);
        }
        return null;
    }

    /**
     * Extract master public key from mobile SDK configuration
     * @param config Mobile SDK configuration.
     * @param stepLogger Step logger instance.
     * @return Master public key.
     */
    public static PublicKey getMasterPublicKey(SdkConfiguration config, StepLogger stepLogger) {
        return convertMasterPublicKey(config.masterPublicKeyBase64(), stepLogger);
    }

    /**
     * Get mobile SDK configuration.
     * @param clientConfigObject Object with configuration.
     * @return Mobile SKD configuration.
     */
    public static String getMobileSdkConfig(JSONObject clientConfigObject) {
        if (clientConfigObject.get("mobileSdkConfig") != null) {
            return (String) clientConfigObject.get("mobileSdkConfig");
        }
        return null;
    }

    /**
     * Convert master public key from String to PublicKey
     * @param masterPublicKey Master public key
     * @param stepLogger Step logger
     * @return Public key
     */
    private static PublicKey convertMasterPublicKey(String masterPublicKey, StepLogger stepLogger) {
        // TODO - support for crypto4
        if (masterPublicKey != null) {
            try {
                byte[] masterKeyBytes = Base64.getDecoder().decode(masterPublicKey);
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
                stepLogger.writeError("master-key-error-cryptography-provider", "Cryptography Provider Error", "Cryptography provider is initialized incorrectly", e);
                stepLogger.writeDoneFailed("master-key-failed");
                System.exit(1);
            } catch (GenericCryptoException e) {
                stepLogger.writeError("master-key-error-cryptography-generic", "Cryptography Generic Error", "Cryptography error occurred", e);
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
