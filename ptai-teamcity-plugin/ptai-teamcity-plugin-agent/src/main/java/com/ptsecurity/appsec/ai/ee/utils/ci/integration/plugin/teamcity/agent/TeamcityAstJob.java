package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.ReportsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations.TeamcityAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations.TeamcityFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
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
public class TeamcityAstJob extends AstJob {
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

    /**
     * Job settings
     */
    private Map<String, String> params;

    /**
     * Global plugin settings
     */
    private Map<String, String> globals;

    @Override
    public boolean unsafeInit() {
        scanType = TRUE.equals(params.get(Params.FULL_SCAN_MODE)) ? ScanType.FULL : ScanType.INCREMENTAL;
        verbose = TRUE.equals(params.get(Params.VERBOSE));

        if (SERVER_SETTINGS_LOCAL.equals(params.get(Params.SERVER_SETTINGS))) globals = params;

        url = globals.get(Params.URL);
        insecure = TRUE.equals(globals.get(Params.INSECURE));
        token = globals.get(Params.TOKEN);
        caCertsPem = globals.get(Params.CERTIFICATES);

        if (AST_SETTINGS_JSON.equals(params.get(Params.AST_SETTINGS))) {
            ScanSettings scanSettings = JsonSettingsHelper.verify(params.get(Params.JSON_SETTINGS));
            name = scanSettings.getProjectName();
            jsonSettings = JsonSettingsHelper.minimize(params.get(Params.JSON_SETTINGS));
            jsonPolicy = JsonPolicyHelper.minimize(params.get(Params.JSON_POLICY));
        } else
            name = params.get(Params.PROJECT_NAME);
        if (Validator.validateNotEmpty(name).fail())
            throw ApiException.raise("Project name is empty", new IllegalArgumentException());

        async = AST_MODE_ASYNC.equals(params.get(Params.AST_MODE));
        if (!async) {
            failIfFailed = TRUE.equals(params.get(Params.FAIL_IF_FAILED));
            failIfUnstable = TRUE.equals(params.get(Params.FAIL_IF_UNSTABLE));
            reports = ReportsHelper.convert(params);
        }

        Transfer transfer = new Transfer();
        if (StringUtils.isNotEmpty(params.get(Params.INCLUDES)))
            transfer.setIncludes(params.get(Params.INCLUDES));
        if (StringUtils.isNotEmpty(params.get(Params.EXCLUDES)))
            transfer.setExcludes(params.get(Params.EXCLUDES));
        if (StringUtils.isNotEmpty(params.get(Params.PATTERN_SEPARATOR)))
            transfer.setPatternSeparator(params.get(Params.PATTERN_SEPARATOR));
        if (StringUtils.isNotEmpty(params.get(Params.REMOVE_PREFIX)))
            transfer.setRemovePrefix(params.get(Params.REMOVE_PREFIX));
        transfer.setFlatten(TRUE.equalsIgnoreCase(params.get(Params.FLATTEN)));
        transfer.setUseDefaultExcludes(TRUE.equalsIgnoreCase(params.get(Params.USE_DEFAULT_EXCLUDES)));
        transfers = new Transfers().addTransfer(transfer);

        astOps = TeamcityAstOperations.builder()
                .owner(this)
                .build();
        fileOps = TeamcityFileOperations.builder()
                .owner(this)
                .build();
        return super.unsafeInit();
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
