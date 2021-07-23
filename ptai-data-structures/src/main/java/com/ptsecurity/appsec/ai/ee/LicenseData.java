package com.ptsecurity.appsec.ai.ee;

import lombok.*;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
public class LicenseData {
    @NonNull
    protected Integer number;

    @NonNull
    protected OffsetDateTime startDate;

    @NonNull
    protected OffsetDateTime endDate;

    @NonNull
    protected Boolean valid;

    @Builder.Default
    protected List<String> languages = new ArrayList<>();
}
