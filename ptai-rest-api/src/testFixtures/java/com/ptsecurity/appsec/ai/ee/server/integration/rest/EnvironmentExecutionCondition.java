package com.ptsecurity.appsec.ai.ee.server.integration.rest;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.support.AnnotationSupport;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class EnvironmentExecutionCondition implements ExecutionCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context){
        ScanBrief.ApiVersion activeEnvironment = Connection.CONNECTION().getVersion();
        if(activeEnvironment == null)
            return ConditionEvaluationResult.disabled("There is no active environment");

        Set<ScanBrief.ApiVersion> enabledEnvironments = getEnabledEnvironment(context);
        // If test not annotated with PT AI version - allow its execution
        if (enabledEnvironments.isEmpty()) return ConditionEvaluationResult.enabled("No environment restrictions");
        return enabledEnvironments.contains(activeEnvironment)
                ? ConditionEvaluationResult.enabled("Active environment is enabled")
                : ConditionEvaluationResult.disabled("Active environment is not enabled");
    }

    private Set<ScanBrief.ApiVersion> getEnabledEnvironment(ExtensionContext context) {
        Set<ScanBrief.ApiVersion> enabledEnvironments = new HashSet<>();
        context.getElement()
                .flatMap(element -> AnnotationSupport.findAnnotation(element, Environment.class)
                .map(Environment::enabledFor))
                .ifPresent(array -> enabledEnvironments.addAll(Arrays.asList(array)));
        return enabledEnvironments;
    }
}