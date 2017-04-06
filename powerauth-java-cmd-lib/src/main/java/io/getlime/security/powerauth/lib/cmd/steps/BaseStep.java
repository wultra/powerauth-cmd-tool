package io.getlime.security.powerauth.lib.cmd.steps;

import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import org.json.simple.JSONObject;

import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public interface BaseStep {

    JSONObject execute(StepLogger logger, Map<String, Object> context) throws Exception;

}
