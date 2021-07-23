package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

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
}
