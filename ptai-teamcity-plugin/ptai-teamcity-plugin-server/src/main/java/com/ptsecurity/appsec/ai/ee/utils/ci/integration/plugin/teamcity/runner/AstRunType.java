package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.*;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.serverSide.RunType;
import jetbrains.buildServer.serverSide.RunTypeRegistry;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class AstRunType extends RunType {

    private final PluginDescriptor descriptor;

    public AstRunType(final RunTypeRegistry runTypeRegistry, final PluginDescriptor descriptor) {
        this.descriptor = descriptor;
        runTypeRegistry.registerRunType(this);
    }

    @NonNull
    @Override
    public String getType() {
        return Constants.RUNNER_TYPE;
    }

    @NonNull
    @Override
    public String getDisplayName() {
        return Labels.RUNNER;
    }

    @NonNull
    @Override
    public String getDescription() {
        return Hints.RUNNER;
    }

    /**
     * @return Properties processor which will be used to validate parameters specified by user
     */
    @Override
    public PropertiesProcessor getRunnerPropertiesProcessor() {
        return new AstRunTypePropertiesProcessor();
    }

    /**
     * @return Absolute path to a JSP file or controller for editing runner parameters, should not include context path
     */
    @Override
    public String getEditRunnerParamsJspFilePath() {
        return this.descriptor.getPluginResourcesPath("editRunParams.jsp");
    }

    /**
     * @return Absolute path to a JSP file or controller for displaying runner parameters, should not include context path
     */
    @Override
    public String getViewRunnerParamsJspFilePath() {
        return this.descriptor.getPluginResourcesPath("viewRunParams.jsp");
    }

    /**
     * Teamcity calls this method to get default job properties. Then UI compares
     * with actual ones and marks fields that are differ as modified
     * @return Map of default field values
     */
    @Override
    public Map<String, String> getDefaultRunnerProperties() {
        final Map<String, String> parameters = new HashMap<>();

        Arrays.stream(Params.class.getDeclaredFields())
                .filter(f -> Modifier.isPublic(f.getModifiers()))
                .filter(f -> Modifier.isStatic(f.getModifiers()))
                .filter(f -> Modifier.isFinal(f.getModifiers()))
                .map(Field::getName)
                .forEach(n -> parameters.put(Params.value(n), Defaults.value(n)));

        return parameters;
    }

    /**
     * Method generates "Parameters description" value in the "Build steps" table
     * @param parameters PT AI AST job parameters map
     * @return PT AI AST job parameters description
     */
    @NonNull
    @Override
    public String describeParameters(@NonNull Map<String, String> parameters) {
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
