package io.getlime.security.powerauth.lib.cmd.steps.pojo;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import lombok.Builder;
import lombok.Data;

@Data @Builder
public class TokenContext {

    private CreateTokenStepModel model;

    private EciesEncryptor encryptor;

    private String password;

    private ResultStatusObject resultStatusObject;

    private StepLogger stepLogger;

}
