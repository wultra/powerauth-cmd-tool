package io.getlime.security.powerauth.lib.cmd.util;

import com.mashape.unirest.http.Headers;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class HttpUtil {

    public static Map<String, String> flattenHttpHeaders(Headers headers) {
        Map<String, String> result = new HashMap<>();
        for (String key : headers.keySet()) {
            String value = headers.getFirst(key);
            result.put(key, value);
        }
        return result;
    }

}
