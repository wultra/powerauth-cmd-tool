package io.getlime.security.powerauth.lib.cmd.logging;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class StepLogger {

    private JsonGenerator generator;
    private OutputStream outputStream;

    public StepLogger(OutputStream outputStream) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        DefaultPrettyPrinter pp = new DefaultPrettyPrinter();
        pp.indentArraysWith( DefaultIndenter.SYSTEM_LINEFEED_INSTANCE );
        pp.indentObjectsWith( DefaultIndenter.SYSTEM_LINEFEED_INSTANCE );
        mapper.setDefaultPrettyPrinter(pp);
        try {
            this.generator = mapper.getFactory().createGenerator(outputStream);
            this.generator.setPrettyPrinter(pp);
            this.outputStream = outputStream;
        } catch (IOException e) {
            //
        }
    }

    private void flush() {
        try {
            generator.flush();
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void start() {
        try {
            generator.writeStartObject();
            generator.writeFieldName("steps");
            generator.writeStartArray();
            flush();
        } catch (IOException e) {
            //
        }
    }

    public void writeItem(String name, String description, String status, Object object) {
        try {
            Map<String, Object> map = new HashMap<>();
            map.put("name", name);
            map.put("description", description);
            map.put("status", status);
            map.put("object", object);
            generator.writeObject(map);
            flush();
        } catch (IOException e) {
            //
        }
    }

    public void writeServerCall(String uri, String method, Object requestObject, Map<String, ?> headers) {
        Map<String, Object> map = new HashMap<>();
        map.put("url", uri);
        map.put("method", method);
        map.put("requestObject", requestObject);
        map.put("requestHeaders", headers);
        String name = "Sending Request";
        String desc = "Calling PowerAuth 2.0 Standard RESTful API endpoint";
        String status = "OK";
        writeItem(name, desc, status, map);
    }

    public void writeServerCallOK(Object responseObject, Map<String, ?> headers) {
        String name = "Response 200 - OK";
        String desc = "Endpoint was called successfully";
        String status = "OK";
        Map<String, Object> map = new HashMap<>();
        map.put("responseObject", responseObject);
        map.put("responseHeaders", headers);
        writeItem(name, desc, status, map);
    }

    public void writeServerCallError(int statusCode, Object responseObject, Map<String, ?> headers) {
        String name = "Response " + statusCode + " - ERROR";
        String desc = "Endpoint was called with an error";
        String status = "ERROR";
        Map<String, Object> map = new HashMap<>();
        map.put("responseObject", responseObject);
        map.put("responseHeaders", headers);
        writeItem(name, desc, status, map);
    }

    public void close() {
        try {
            generator.writeEndArray();
            generator.writeEndObject();
            flush();
            generator.close();
        } catch (IOException e) {
            //
        }
    }

    public void writeServerCallConnectionError(Exception e) {
        String name = "Connection Error";
        String desc = "Connection refused";
        String status = "ERROR";
        writeItem(name, desc, status, e);
    }

    public void writeError(String errorMessage) {
        writeError(null, errorMessage, null);
    }

    public void writeError(Exception exception) {
        writeError(null, exception.getMessage(), exception);
    }

    public void writeError(String name, String errorMessage) {
        writeError(name, errorMessage, null);
    }

    public void writeError(String name, String errorMessage, Exception exception) {
        String desc = errorMessage;
        String status = "ERROR";
        writeItem(name, desc, status, exception);
    }

    public void writeDoneOK() {
        String name = "Done";
        String desc = "Execution has successfully finished";
        String status = "DONE";
        writeItem(name, desc, status, null);
    }

    public void writeDoneFailed() {
        String name = "Done";
        String desc = "Execution has failed";
        String status = "FAILED";
        writeItem(name, desc, status, null);
    }

}
