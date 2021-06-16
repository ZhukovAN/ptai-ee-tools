package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.deser.std.StdScalarDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.IssueLevel;

import java.io.IOException;

public class BaseJsonHelper {
    /**
     * Custom deserializer for auto-generated {@link IssueLevel} class. Need to implement
     * this one as standard EnumDeserializer supports only enums with sequential integer
     * values starting with zero and lacks ability to deserialize values like 10 / 20 / 30 etc
     */
    public static class IssueLevelDeserializer extends StdScalarDeserializer<IssueLevel> {

        public IssueLevelDeserializer() {
            this(null);
        }

        @Override
        public IssueLevel deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            if (JsonToken.VALUE_STRING.equals(p.currentToken()))
                return IssueLevel.valueOf(p.getValueAsString());
            else
                return IssueLevel.fromValue(p.getIntValue());
        }

        public IssueLevelDeserializer(Class<?> vc) {
            super(vc);
        }
    }

    public static ObjectMapper createObjectMapper() {
        // Create IssuesModel deserializer
        ObjectMapper mapper = new ObjectMapper();
        // Need this as JSONs like aiproj settings may contain comments
        mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
        // Need this as JSON report contains "Descriptions" while IssuesModel have "descriptions"
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES);
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
        // Need this as IssuesModel JSON report contains fields like "link" that are missing from IssueDescriptionModel
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        SimpleModule module = new SimpleModule();
        module.addDeserializer(IssueLevel.class, new IssueLevelDeserializer());
        mapper.registerModule(module);

        return mapper;
    }
}
