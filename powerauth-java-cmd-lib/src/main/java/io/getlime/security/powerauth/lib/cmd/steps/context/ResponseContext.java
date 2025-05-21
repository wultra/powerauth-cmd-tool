package io.getlime.security.powerauth.lib.cmd.steps.context;

import lombok.Builder;
import lombok.Data;
import org.springframework.http.ResponseEntity;

/**
 * Response context
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data
@Builder
public class ResponseContext<R> {

    /**
     * Response body object
     */
    private R responseBodyObject;

    /**
     * HTTP response entity
     */
    private ResponseEntity<R> responseEntity;

    /**
     * HTTP response payload (decrypted from the response entity)
     */
    private Object responsePayloadDecrypted;

}
