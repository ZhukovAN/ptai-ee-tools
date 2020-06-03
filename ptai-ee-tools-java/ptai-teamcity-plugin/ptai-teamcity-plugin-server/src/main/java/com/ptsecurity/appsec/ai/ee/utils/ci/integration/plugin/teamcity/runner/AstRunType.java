package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Hints;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.serverSide.RunType;
import jetbrains.buildServer.serverSide.RunTypeRegistry;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

public class AstRunType extends RunType {

    private final PluginDescriptor descriptor;

    public AstRunType(final RunTypeRegistry runTypeRegistry, final PluginDescriptor descriptor) {
        this.descriptor = descriptor;
        runTypeRegistry.registerRunType(this);
    }

    @NotNull
    @Override
    public String getType() {
        return Constants.RUNNER_TYPE;
    }

    @NotNull
    @Override
    public String getDisplayName() {
        return Labels.RUNNER;
    }

    @NotNull
    @Override
    public String getDescription() {
        return Hints.RUNNER;
    }

    /**
     * @return Properties processor which will be used to validate parameters specified by user
     */
    @Nullable
    @Override
    public PropertiesProcessor getRunnerPropertiesProcessor() {
        return new AstRunTypePropertiesProcessor();
    }

    /**
     * @return Absolute path to a JSP file or controller for editing runner parameters, should not include context path
     */
    @Nullable
    @Override
    public String getEditRunnerParamsJspFilePath() {
        return this.descriptor.getPluginResourcesPath("editRunParams.jsp");
    }

    /**
     * @return Absolute path to a JSP file or controller for displaying runner parameters, should not include context path
     */
    @Nullable
    @Override
    public String getViewRunnerParamsJspFilePath() {
        return this.descriptor.getPluginResourcesPath("viewRunParams.jsp");
    }

    @Nullable
    @Override
    public Map<String, String> getDefaultRunnerProperties() {
        Map<String, String> parameters = new HashMap<>();

        parameters.put(Params.SCAN_SETTINGS, Constants.SETTINGS_UI);
        parameters.put(Params.PROJECT_NAME, "");
        parameters.put(Params.JSON_SETTINGS, "");
        parameters.put(Params.JSON_POLICY, "");
        parameters.put(Params.FAIL_IF_FAILED, Constants.TRUE);
        parameters.put(Params.FAIL_IF_UNSTABLE, Constants.FALSE);

        parameters.put(Params.NODE_NAME, Base.DEFAULT_PTAI_NODE_NAME);
        parameters.put(Params.VERBOSE, Constants.FALSE);
        parameters.put(Params.INCLUDES, Transfer.DEFAULT_INCLUDES);
        parameters.put(Params.REMOVE_PREFIX, "");
        parameters.put(Params.EXCLUDES, Transfer.DEFAULT_EXCLUDES);
        parameters.put(Params.PATTERN_SEPARATOR, Transfer.DEFAULT_PATTERN_SEPARATOR);
        parameters.put(Params.USE_DEFAULT_EXCLUDES, Transfer.DEFAULT_USE_DEFAULT_EXCLUDES ? Constants.TRUE : Constants.FALSE);
        parameters.put(Params.FLATTEN, Transfer.DEFAULT_FLATTEN ? Constants.TRUE : Constants.FALSE);

        return parameters;
    }
}
