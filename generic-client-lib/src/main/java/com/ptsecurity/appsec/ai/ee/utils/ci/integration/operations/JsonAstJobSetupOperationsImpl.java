package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

import java.util.UUID;

@SuperBuilder
public class JsonAstJobSetupOperationsImpl implements SetupOperations {
    @NonNull
    protected GenericAstJob owner;

    @Setter
    @NonNull
    protected String jsonSettings;

    @Setter
    protected String jsonPolicy;

    public UUID setupProject() throws GenericException {
        // Check if JSON settings and policy are defined correctly. Throw an exception if there are problems
        AiProjScanSettings settings = (StringUtils.isEmpty(jsonSettings))
                ? null
                : JsonSettingsHelper.verify(jsonSettings);
        if (null == settings)
            throw GenericException.raise("JSON settings must not be empty", new IllegalArgumentException());
        if (StringUtils.isEmpty(settings.getProjectName()))
            throw GenericException.raise("Project name in JSON settings must not be empty", new IllegalArgumentException());
        owner.setProjectName(settings.getProjectName());

        // If fullScanMode is false, but incremental scan is disabled, use fullScanMode indeed
        owner.setFullScanMode(owner.isFullScanMode() || !settings.getUseIncrementalScan());

        Policy[] policy = (StringUtils.isEmpty(jsonPolicy))
                ? null
                : JsonPolicyHelper.verify(jsonPolicy);
        ProjectTasks projectTasks = new Factory().projectTasks(owner.getClient());
        return projectTasks.setupFromJson(settings, policy);
    }
}
