package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.JsonAstJobSetupOperationsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.UiAstJobSetupOperationsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.ReportsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations.TeamcityAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations.TeamcityFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import jetbrains.buildServer.agent.AgentRunningBuild;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;

@Getter
@Setter
@SuperBuilder
public class TeamcityAstJob extends GenericAstJob implements TextOutput {
    /**
     * Teamcity agent where AST is going on. We need this
     * interface to execute file opertaions
     */
    @NonNull
    private AgentRunningBuild agent;

    /**
     * List of transfers, i.e. source files to be zipped
     * and sent to PT AI server
     */
    private List<Transfer> transfers;

    @NonNull
    private ArtifactsWatcher artifactsWatcher;

    protected String settings;

    protected String policy;

    @Override
    protected void init() throws GenericException {
        astOps = TeamcityAstOperations.builder()
                .owner(this)
                .build();
        fileOps = TeamcityFileOperations.builder()
                .owner(this)
                .build();
        if (null != settings)
            setupOps = JsonAstJobSetupOperationsImpl.builder()
                    .jsonSettings(settings)
                    .jsonPolicy(policy)
                    .owner(this)
                    .build();
        else
            setupOps = UiAstJobSetupOperationsImpl.builder()
                    .owner(this)
                    .build();
    }

    @Override
    protected void out(final String value) {
        if (null == value) return;
        agent.getBuildLogger().message(value);
    }

    @Override
    protected void out(final Throwable t) {
        if (null == t) return;
        agent.getBuildLogger().exception(t);
    }
}
