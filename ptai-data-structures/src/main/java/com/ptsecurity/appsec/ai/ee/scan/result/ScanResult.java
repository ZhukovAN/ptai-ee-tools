package com.ptsecurity.appsec.ai.ee.scan.result;

import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.*;

@SuperBuilder
@NoArgsConstructor
public class ScanResult extends ScanBrief {
    /**
     * As AST result issues list may be big (for example, OWASP Benchmark
     * issues JSON is 75 megabytes and during its parsing JVM consumes
     * additional 2 GB RAM), PT AI server response parse may throw
     * OutOfMemoryException. This field equals true if parse successfully
     * finished
     */
    @Getter
    @Setter
    @Builder.Default
    protected boolean issuesParseState = false;

    @Getter
    protected final List<BaseIssue> issues = new ArrayList<>();
}