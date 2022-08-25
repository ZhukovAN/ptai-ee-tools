package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import lombok.*;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PluginVersions {
    @NonNull
    protected String generationTimestamp;

    @NonNull
    protected Map<String, Map<String, Plugin>> plugins;
}
