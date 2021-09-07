package io.getlime.security.powerauth.lib.cmd.steps.pojo;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import lombok.Builder;
import lombok.Data;

import java.security.KeyPair;

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
