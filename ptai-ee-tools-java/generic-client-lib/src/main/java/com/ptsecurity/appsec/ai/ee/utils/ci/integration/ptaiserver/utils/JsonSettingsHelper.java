package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

public class JsonSettingsHelper {
    public static ScanSettings verify(String json) throws ApiException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            ScanSettings res = mapper.readValue(json, ScanSettings.class);
            if (StringUtils.isEmpty(res.getProjectName())) throw new Exception("ProjectName field is not defined or empty");
            if (null == res.getProgrammingLanguage()) throw new Exception("ProgrammingLanguage field is not defined or empty");
            return res;
        } catch (Exception e) {
            throw ApiException.raise("JSON settings parse failed", e);
        }
    }

    public static String serialize(ScanSettings settings) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(settings.fix());
        } catch (JsonProcessingException e) {
            throw ApiException.raise("JSON settings serialization failed", e);
        }
    }

    /**
     * @param settingsJson JSON-defined AST settings
     * @return Minimized JSON-defined AST settings, i.e. without comments, formatting etc.
     * @throws ApiException
     */
    public static String minimize(@NonNull String settingsJson) throws ApiException {
        ScanSettings settings = verify(settingsJson);
        return serialize(settings);
    }
}
