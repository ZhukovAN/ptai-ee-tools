package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import lombok.NonNull;

import java.io.IOException;

public class JsonPolicyVerifier {
    public static Policy[] verify(String json) throws PtaiClientException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            Policy[] res = mapper.readValue(json, Policy[].class);
            return res;
        } catch (IOException e) {
            throw new PtaiClientException("JSON policy parse failed", e);
        }
    }

    public static String serialize(Policy[] policy) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(policy);
        } catch (JsonProcessingException e) {
            throw new PtaiClientException("JSON policy serialization failed", e);
        }
    }

    /**
     * @param policyJson JSON-defined AST policy
     * @return Minimized JSON-defined AST policy, i.e. without comments, formatting etc.
     * @throws PtaiClientException
     */
    public static String minimize(@NonNull String policyJson) throws PtaiClientException {
        Policy[] policy = verify(policyJson);
        return serialize(policy);
    }
}
