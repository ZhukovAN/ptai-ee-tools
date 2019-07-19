package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

public class JsonSettingsVerifier {
    public static JsonSettings verify(String json) throws PtaiClientException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            JsonSettings res = mapper.readValue(json, JsonSettings.class);
            if (StringUtils.isEmpty(res.ProjectName)) throw new Exception("ProjectName is not defined or empty");
            if (StringUtils.isEmpty(res.ProgrammingLanguage)) throw new Exception("ProgrammingLanguage is not defined or empty");
            return res;
        } catch (Exception e) {
            throw new PtaiClientException("JSON settings parse failed", e);
        }
    }
}
