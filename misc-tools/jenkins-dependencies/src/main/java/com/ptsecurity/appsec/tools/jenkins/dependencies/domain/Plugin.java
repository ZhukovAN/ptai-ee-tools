package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

import java.util.List;

@Getter
@AllArgsConstructor
public class Plugin {
    protected final String buildDate;

    @Getter
    @AllArgsConstructor
    public static class Dependency {
        @NonNull
        protected final String name;
        protected final boolean optional;
        @NonNull
        protected final String version;
    }

    protected final List<Dependency> dependencies;

    protected final String name;
    protected final String requiredCore;
    protected final String sha1;
    protected final String sha256;
    protected final String url;
    protected final String version;
}
