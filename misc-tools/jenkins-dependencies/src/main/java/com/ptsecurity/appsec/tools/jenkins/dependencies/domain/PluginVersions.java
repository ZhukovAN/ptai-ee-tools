package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

@Getter
@AllArgsConstructor
public class PluginVersions {
    @NonNull
    protected final String generationTimestamp;

}
