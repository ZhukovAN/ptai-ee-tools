package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@ToString
public class Plugin {
    protected String buildDate;

    @Getter
    @Setter
    @NoArgsConstructor
    @ToString
    public static class Dependency {
        @NonNull
        protected String name;
        protected boolean optional;
        @NonNull
        protected String version;
    }

    @ToString.Exclude
    protected List<Dependency> dependencies;

    protected String name;
    protected String requiredCore;

    @ToString.Exclude
    protected String sha1;

    @ToString.Exclude
    protected String sha256;
    protected String url;
    protected String version;
}
