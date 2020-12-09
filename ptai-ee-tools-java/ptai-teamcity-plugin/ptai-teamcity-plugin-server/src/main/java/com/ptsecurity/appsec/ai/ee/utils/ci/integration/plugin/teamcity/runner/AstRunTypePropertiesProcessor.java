package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.PropertiesProcessor;

import java.util.Collection;
import java.util.Map;

public class AstRunTypePropertiesProcessor implements PropertiesProcessor {
    @Override
    public Collection<InvalidProperty> process(Map<String, String> properties) {
        return null;
    }
}
