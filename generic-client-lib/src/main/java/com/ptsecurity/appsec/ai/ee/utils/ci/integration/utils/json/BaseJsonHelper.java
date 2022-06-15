package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.Iterator;
import java.util.Map;
import java.util.function.Function;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
public class BaseJsonHelper {
    public static ObjectMapper createObjectMapper() {
        return new ObjectMapper()
                // Need this as JSONs like aiproj settings may contain comments
                .enable(JsonParser.Feature.ALLOW_COMMENTS)
                // Need this as JSON report contains "Descriptions" while IssuesModel have "descriptions"
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES)
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
                // Need this as IssuesModel JSON report contains fields like "link" that are missing from IssueDescriptionModel
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public static String serialize(Object data) throws GenericException {
        return call(
                () -> new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(data),
                "JSON settings serialization failed");
    }

    /**
     * @param json JSON-defined object
     * @return Minimized JSON-defined object, i.e. without comments, formatting etc.
     * @throws GenericException
     */
    public static String minimize(@NonNull String json) throws GenericException {
        JsonNode root = call(() -> createObjectMapper().readTree(json), "JSON read failed");
        return call(
                () -> new ObjectMapper().writeValueAsString(root),
                "JSON serialization failed");
    }

    protected static void processJsonNode(final String name, @NonNull final JsonNode node, @NonNull Function<String, String> converter) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            fields.forEachRemaining(field -> {
                if (field.getValue().isTextual()) {
                    log.trace("Process {} field", name);
                    ObjectNode objectNode = (ObjectNode) node;
                    objectNode.put(field.getKey(), converter.apply(field.getValue().asText()));
                } else if (field.getValue().isObject())
                    processJsonNode(field.getKey(), field.getValue(), converter);
            });
        } else if (node.isArray()) {
            log.trace("Process JSON array nameless nodes");
            ArrayNode arrayField = (ArrayNode) node;
            arrayField.forEach(item -> { processJsonNode(null, item, converter); });
        }
    }

    public static String replaceMacro(@NonNull String json, @NonNull Function<String, String> converter) throws GenericException {
        JsonNode root = call(() -> createObjectMapper().readTree(json), "JSON read failed");
        log.trace("Process JSON nameless root node");
        processJsonNode(null, root, converter);
        return call(
                () -> new ObjectMapper().writeValueAsString(root),
                "JSON serialization failed");
    }
}
