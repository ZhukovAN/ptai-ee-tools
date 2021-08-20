package com.ptsecurity.appsec.ai.ee.scan.sources;

import lombok.*;

import java.io.Serializable;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Transfer implements Serializable {
    public static final String DEFAULT_INCLUDES = "**/*";
    public static final String DEFAULT_EXCLUDES = "**/.ptai/**";
    public static final String DEFAULT_REMOVE_PREFIX = "";
    public static final String DEFAULT_PATTERN_SEPARATOR = "[, ]+";
    public static final boolean DEFAULT_USE_DEFAULT_EXCLUDES = true;
    public static final boolean DEFAULT_FLATTEN = false;
    @Builder.Default
    protected String includes = DEFAULT_INCLUDES;
    @Builder.Default
    protected String removePrefix = DEFAULT_REMOVE_PREFIX;
    @Builder.Default
    protected String excludes = DEFAULT_EXCLUDES;
    @Builder.Default
    protected String patternSeparator = DEFAULT_PATTERN_SEPARATOR;
    @Builder.Default
    protected boolean useDefaultExcludes = false;
    @Builder.Default
    protected boolean flatten = false;
}