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
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import lombok.Builder;
import lombok.Data;

import java.security.KeyPair;

/**
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data @Builder
public class ActivationContext {

    private CreateActivationStepModel modelCreate;

    private PrepareActivationStepModel modelPrepare;

    private KeyPair deviceKeyPair;

    private EciesEncryptor eciesEncryptorL1;

    private EciesEncryptor eciesEncryptorL2;

    private ResultStatusObject resultStatusObject;

    private String password;

    private StepLogger stepLogger;

}
