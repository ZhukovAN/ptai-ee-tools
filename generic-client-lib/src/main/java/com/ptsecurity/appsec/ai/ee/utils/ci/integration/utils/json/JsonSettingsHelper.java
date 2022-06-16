package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language;
import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
public class JsonSettingsHelper extends BaseJsonHelper {
    protected ObjectNode root;

    public JsonSettingsHelper(@NonNull final String json) throws GenericException {
        if (StringUtils.isEmpty(json)) throw GenericException.raise("Empty JSON settings passed", new IllegalArgumentException());
        root = call(() -> (ObjectNode) createObjectMapper().readTree(json), "JSON parse failed");
    }

    protected static void setStringField(@NonNull final ObjectNode node, @NonNull final String fieldName, final String fieldValue) {
        if (!StringUtils.isEmpty(fieldValue))
            node.put(fieldName, fieldValue);
        else if (node.has(fieldName))
            node.remove(fieldName);
    }

    protected static String getStringField(@NonNull final ObjectNode node, @NonNull final String fieldName) {
        if (node.has(fieldName) && StringUtils.isNotEmpty(node.get(fieldName).asText())) return node.get(fieldName).asText();
        return null;
    }

    private final String PROJECT_NAME = "ProjectName";

    public void setProjectName(@NonNull final String value) {
        setStringField(root, PROJECT_NAME, value);
    };

    public String getProjectName() {
        return getStringField(root, PROJECT_NAME);
    };

    public JsonSettingsHelper projectName(@NonNull final String value) {
        setProjectName(value);
        return this;
    }

    private final String PROGRAMMING_LANGUAGE = "ProgrammingLanguage";

    public void setProgrammingLanguage(final Language value) {
        if (null != value)
            root.put(PROGRAMMING_LANGUAGE, value.name());
        else if (root.has(PROGRAMMING_LANGUAGE))
            root.remove(PROGRAMMING_LANGUAGE);
    };

    public Language getProgrammingLanguage() throws GenericException {
        if (!root.has(PROGRAMMING_LANGUAGE) || StringUtils.isEmpty(root.get(PROGRAMMING_LANGUAGE).asText())) return null;
        String value = root.get(PROGRAMMING_LANGUAGE).asText().trim();
        return call(
                () -> Language.fromString(value),
                "Invalid " + PROGRAMMING_LANGUAGE + " field value " + value);
    };

    public JsonSettingsHelper programmingLanguage(@NonNull final Language value) {
        setProgrammingLanguage(value);
        return this;
    }

    public JsonSettingsHelper verifyRequiredFields() throws GenericException {
        call(() -> {
            if (StringUtils.isEmpty(getProjectName()))
                throw new IllegalArgumentException("ProjectName field is not defined or empty");
            if (null == getProgrammingLanguage())
                throw new IllegalArgumentException("ProgrammingLanguage field is not defined or empty");
        }, "JSON settings parse failed");
        return this;
    }

    public String serialize() {
        String result = call(
                () -> new ObjectMapper().writeValueAsString(root),
                "JSON serialization failed");
        log.trace("Serialized settings: {}", result);
        return result;
    }
}
