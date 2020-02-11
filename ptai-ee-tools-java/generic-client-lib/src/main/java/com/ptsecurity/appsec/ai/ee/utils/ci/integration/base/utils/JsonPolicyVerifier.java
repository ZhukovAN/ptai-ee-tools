package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;

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
}
