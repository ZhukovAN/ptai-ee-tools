package com.ptsecurity.appsec.ai.ee.ptai.server.api.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.JSON;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.IssuesModel;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.io.InputStream;
import java.io.InputStreamReader;

public class IssuesModelJsonHelper {
    @SneakyThrows
    public static IssuesModel parse(@NonNull final InputStream data) {
        JSON parser = new JSON();
        return parser.getGson().fromJson(new InputStreamReader(data), IssuesModel.class);
    }
}
