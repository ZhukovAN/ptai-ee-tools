package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Transfer {
    public static final String DEFAULT_INCLUDES = "**/*";
    public static final String DEFAULT_EXCLUDES = "";
    public static final String DEFAULT_PATTERN_SEPARATOR = "[, ]+";
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