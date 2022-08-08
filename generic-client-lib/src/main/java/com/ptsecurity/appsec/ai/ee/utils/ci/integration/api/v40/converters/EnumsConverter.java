package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.converters;

import com.ptsecurity.appsec.ai.ee.server.v40.projectmanagement.model.Stage;
import lombok.NonNull;

import java.util.HashMap;
import java.util.Map;

public class EnumsConverter {
    public static final Map<Stage, com.ptsecurity.appsec.ai.ee.scan.progress.Stage> STAGE_MAP = new HashMap<>();

    static {
        for (Stage stage : Stage.values())
            STAGE_MAP.put(stage, com.ptsecurity.appsec.ai.ee.scan.progress.Stage.valueOf(stage.name()));
    }

    @NonNull
    public static com.ptsecurity.appsec.ai.ee.scan.progress.Stage convert(@NonNull final Stage stage) {
        return STAGE_MAP.get(stage);
    }
}