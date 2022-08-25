package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class Plugin {
    protected String buildDate;

    @Getter
    @Setter
    @NoArgsConstructor
    public static class Dependency {
        @NonNull
        protected String name;
        protected boolean optional;
        @NonNull
        protected String version;
    }

    protected List<Dependency> dependencies;

    protected String name;
    protected String requiredCore;
    protected String sha1;
    protected String sha256;
    protected String url;
    protected String version;
}
