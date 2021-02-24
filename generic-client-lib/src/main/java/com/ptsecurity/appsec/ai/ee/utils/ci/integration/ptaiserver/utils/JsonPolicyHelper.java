package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

public class JsonPolicyHelper {
    public static Policy[] verify(final String json) throws ApiException {
        if (StringUtils.isEmpty(json)) return null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            Policy[] res = mapper.readValue(json, Policy[].class);
            return res;
        } catch (IOException e) {
            throw ApiException.raise("JSON policy parse failed", e);
        }
    }

    public static String serialize(@NonNull final Policy[] policy) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(policy);
        } catch (JsonProcessingException e) {
            throw ApiException.raise("JSON policy serialization failed", e);
        }
    }

    /**
     * @param policyJson JSON-defined AST policy
     * @return Minimized JSON-defined AST policy, i.e. without comments, formatting etc.
     * @throws ApiException
     */
    public static String minimize(@NonNull String policyJson) throws ApiException {
        Policy[] policy = verify(policyJson);
        return serialize(policy);
    }
}
