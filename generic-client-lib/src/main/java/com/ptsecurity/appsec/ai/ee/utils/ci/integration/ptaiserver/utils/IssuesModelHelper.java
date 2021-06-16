package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.IssuesModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.NonNull;

import java.io.IOException;
import java.io.InputStream;

public class IssuesModelHelper extends BaseJsonHelper {
    public static IssuesModel parse(@NonNull final InputStream data) throws ApiException {
        // Create IssuesModel deserializer
        ObjectMapper mapper = createObjectMapper();
        try {
            return mapper.readValue(data, IssuesModel.class);
        } catch (IOException e) {
            throw ApiException.raise("JSON issues model parse failed", e);
        }
    }


}
