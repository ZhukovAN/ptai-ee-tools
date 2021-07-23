package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

public class JsonSettingsHelper extends BaseJsonHelper {
    public static AiProjScanSettings verify(String json) throws GenericException {
        return call(() -> {
            ObjectMapper mapper = createObjectMapper();
            AiProjScanSettings res = mapper.readValue(json, AiProjScanSettings.class);
            if (StringUtils.isEmpty(res.getProjectName()))
                throw new IllegalArgumentException("ProjectName field is not defined or empty");
            if (null == res.getProgrammingLanguage())
                throw new IllegalArgumentException("ProgrammingLanguage field is not defined or empty");
            return res.fix();
        }, "JSON settings parse failed");
    }

    public static String serialize(AiProjScanSettings settings) throws GenericException {
        return call(
                () -> new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(settings.fix()),
                "JSON settings serialization failed");
    }

    /**
     * @param settingsJson JSON-defined AST settings
     * @return Minimized JSON-defined AST settings, i.e. without comments, formatting etc.
     * @throws GenericException
     */
    public static String minimize(@NonNull String settingsJson) throws GenericException {
        AiProjScanSettings settings = verify(settingsJson);
        return serialize(settings);
    }
}
