/*
 * Wultra Antivirus Server and Related Components
 * Copyright (c) 2021, Wultra s.r.o. (www.wultra.com).
 *
 * All rights reserved. This source code can be used only for purposes specified
 * by the given license contract signed by the rightful deputy of Wultra s.r.o.
 * This source code can be used only by the owner of the license.
 *
 * Any disputes arising in respect of this agreement (license) shall be brought
 * before the Municipal Court of Prague.
 */
package io.getlime.security.powerauth.lib.cmd.steps.pojo;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import lombok.Builder;
import lombok.Data;

/**
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data @Builder
public class TokenContext {

    private CreateTokenStepModel model;

    private EciesEncryptor encryptor;

    private String password;

    private ResultStatusObject resultStatusObject;

    private StepLogger stepLogger;

}
