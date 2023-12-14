package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;
import org.apache.commons.lang3.tuple.Pair;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanDiagnostic {
    @Getter
    @Setter
    @NonNull
    @Builder.Default
    protected ScanBrief.State state = ScanBrief.State.UNKNOWN;

    @Getter
    @Setter
    @NonNull
    @Builder.Default
    @JsonProperty
    protected Policy.State policyState = Policy.State.NONE;

    @Getter
    @Setter
    @JsonProperty
    protected String ptaiAgentName;

    @NonNull
    @Getter
    @Setter
    @Builder.Default
    @JsonProperty
    protected List<Error> errors = new ArrayList<>();

    @Getter
    private static class Performance {
        /**
         * AST stage start ISO8601-formatted timestamp
         */
        @NonNull
        protected final String start;

        /**
         * AST stage ISO8601-formatted duration
         */
        @NonNull
        protected final String duration;

        public Performance(@NonNull final Pair<ZonedDateTime, Duration> performance) {
            this.start = performance.getKey().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            this.duration = performance.getValue().toString();
        }
    }

    @NonNull
    @Getter
    @Setter
    @Builder.Default
    @JsonProperty
    protected Map<Stage, Performance> performance = new LinkedHashMap<>();

    public static ScanDiagnostic create(
            @NonNull final ScanBrief scanBrief,
            final List<Error> errors,
            final Map<Stage, Pair<ZonedDateTime, Duration>> performance) {
        ScanDiagnostic result = ScanDiagnostic.builder()
                .state(scanBrief.getState())
                .policyState(scanBrief.getPolicyState())
                .ptaiAgentName(scanBrief.getPtaiAgentName())
                .build();
        if (null != errors) result.getErrors().addAll(errors);
        if (null != performance)
            for (Stage stage : performance.keySet())
                result.getPerformance().put(stage, new Performance(performance.get(stage)));
        return result;
    }
}
