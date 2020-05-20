package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

public class JsonSettingsVerifier {
    public static ScanSettings verify(String json) throws PtaiClientException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            ScanSettings res = mapper.readValue(json, ScanSettings.class);
            if (StringUtils.isEmpty(res.getProjectName())) throw new Exception("ProjectName is not defined or empty");
            if (StringUtils.isEmpty(res.getProgrammingLanguage())) throw new Exception("ProgrammingLanguage is not defined or empty");
            return res;
        } catch (Exception e) {
            throw new PtaiClientException("JSON settings parse failed", e);
        }
    }

    public static String serialize(ScanSettings settings) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(settings.fix());
        } catch (JsonProcessingException e) {
            throw new PtaiClientException("JSON settings serialization failed", e);
        }
    }

    /**
     * @param settingsJson JSON-defined AST settings
     * @return Minimized JSON-defined AST settings, i.e. without comments, formatting etc.
     * @throws PtaiClientException
     */
    public static String minimize(@NonNull String settingsJson) throws PtaiClientException {
        ScanSettings settings = verify(settingsJson);
        return serialize(settings);
    }
}
