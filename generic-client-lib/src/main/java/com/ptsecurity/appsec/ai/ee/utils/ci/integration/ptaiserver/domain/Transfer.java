package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain;

import lombok.*;

import java.io.Serializable;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Transfer implements Serializable {
    public static final String DEFAULT_INCLUDES = "**/*";
    public static final String DEFAULT_EXCLUDES = "**/.ptai/**";
    public static final String DEFAULT_PATTERN_SEPARATOR = "[, ]+";
    public static final boolean DEFAULT_USE_DEFAULT_EXCLUDES = true;
    public static final boolean DEFAULT_FLATTEN = false;
    @Builder.Default
    private String includes = DEFAULT_INCLUDES;
    @Builder.Default
    private String removePrefix = "";
    @Builder.Default
    private String excludes = DEFAULT_EXCLUDES;
    @Builder.Default
    private String patternSeparator = DEFAULT_PATTERN_SEPARATOR;
    @Builder.Default
    private boolean useDefaultExcludes = false;
    @Builder.Default
    private boolean flatten = false;
}