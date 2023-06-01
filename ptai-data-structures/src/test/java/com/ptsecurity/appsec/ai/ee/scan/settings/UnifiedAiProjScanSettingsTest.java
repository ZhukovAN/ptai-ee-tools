package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

class UnifiedAiProjScanSettingsTest {
    @Test
    @DisplayName("Serialize unified AIPROJ settings")
    public void serializeToJson() {
        String data = getResourceString("json/scan/settings/v11/settings.full.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        String json = settings.toJson();
        @NonNull UnifiedAiProjScanSettings clonedSettings = UnifiedAiProjScanSettings.loadSettings(json);
        Assertions.assertEquals(settings.getProgrammingLanguage(), clonedSettings.getProgrammingLanguage());
        clonedSettings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.KOTLIN);
        Assertions.assertNotEquals(settings.getProgrammingLanguage(), clonedSettings.getProgrammingLanguage());
    }

    @SneakyThrows
    @Test
    @DisplayName("Validate JSON schema")
    public void validateJsonSchema() {
        String schema = "{\n" +
                "    \"$schema\": \"http://json-schema.org/draft-04/schema#\",\n" +
                "    \"properties\": {\n" +
                "        \"$schema\": {\n" +
                "            \"type\": \"string\"\n" +
                "        },\n" +
                "        \"Version\": {\n" +
                "            \"type\": \"string\"\n" +
                "        }\n" +
                "    },\n" +
                "\t\"additionalProperties\": false,\n" +
                "    \"required\": [\"Version\"],\n" +
                "    \"title\": \"test\",\n" +
                "    \"type\": \"object\"\n" +
                "}\n";
        JsonSchemaFactory factory = JsonSchemaFactory
                .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4))
                .addMetaSchema(JsonMetaSchema
                        .builder(JsonMetaSchema.getV4().getUri(), JsonMetaSchema.getV4())
                        .build()).build();
        JsonSchema jsonSchema = factory.getSchema(schema);
        Set<ValidationMessage> errors = jsonSchema.validate(createObjectMapper().readTree("{ \"Version\": \"First\" }"));
        Assertions.assertTrue(errors.isEmpty());
        errors = jsonSchema.validate(createObjectMapper().readTree("{ \"Version\": \"First\", \"Unknown\": \"Some data\" }"));
        Assertions.assertFalse(errors.isEmpty());
    }

}