package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.*;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.serverSide.RunType;
import jetbrains.buildServer.serverSide.RunTypeRegistry;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.apache.commons.lang3.StringUtils;
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

        parameters.put(Params.SERVER_SETTINGS, Defaults.SERVER_SETTINGS);

        parameters.put(Params.AST_SETTINGS, Defaults.AST_SETTINGS);
        parameters.put(Params.PROJECT_NAME, Defaults.PROJECT_NAME);
        parameters.put(Params.JSON_SETTINGS, Defaults.JSON_SETTINGS);
        parameters.put(Params.JSON_POLICY, Defaults.JSON_POLICY);
        parameters.put(Params.FAIL_IF_FAILED, Defaults.FAIL_IF_FAILED);
        parameters.put(Params.FAIL_IF_UNSTABLE, Defaults.FAIL_IF_UNSTABLE);

        parameters.put(Params.VERBOSE, Defaults.VERBOSE);
        parameters.put(Params.INCLUDES, Defaults.INCLUDES);
        parameters.put(Params.REMOVE_PREFIX, Defaults.REMOVE_PREFIX);
        parameters.put(Params.EXCLUDES, Defaults.EXCLUDES);
        parameters.put(Params.PATTERN_SEPARATOR, Defaults.PATTERN_SEPARATOR);
        parameters.put(Params.USE_DEFAULT_EXCLUDES, Defaults.USE_DEFAULT_EXCLUDES);
        parameters.put(Params.FLATTEN, Defaults.FLATTEN);

        parameters.put(Params.REPORT_SETTINGS, Defaults.REPORT_SETTINGS);

        return parameters;
    }

    /**
     * Method generates "Parameters description" value in the "Build steps" table
     * @param parameters PT AI AST job parameters map
     * @return PT AI AST job parameters description
     */
    @NotNull
    @Override
    public String describeParameters(@NotNull Map<String, String> parameters) {
        StringBuilder result = new StringBuilder();
        String includes = parameters.getOrDefault(Params.INCLUDES, "");
        if (StringUtils.isNotEmpty(includes))
            result.append("Files to scan: ").append(includes);
        String excludes = parameters.getOrDefault(Params.EXCLUDES, "");
        if (StringUtils.isNotEmpty(excludes))
            result.append(" except: ").append(excludes);
        return result.toString();
    }

}
