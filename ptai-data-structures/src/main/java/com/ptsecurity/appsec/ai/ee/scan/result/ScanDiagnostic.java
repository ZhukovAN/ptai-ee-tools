package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

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

    public static ScanDiagnostic create(@NonNull final ScanBrief scanBrief, final List<Error> errors) {
        ScanDiagnostic result = ScanDiagnostic.builder()
                .state(scanBrief.getState())
                .policyState(scanBrief.getPolicyState())
                .ptaiAgentName(scanBrief.getPtaiAgentName())
                .build();
        if (null != errors) result.getErrors().addAll(errors);
        return result;
    }
}
