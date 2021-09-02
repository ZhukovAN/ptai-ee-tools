package com.ptsecurity.appsec.ai.ee;

import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
public class HealthData {
    @Getter
    @Setter
    @Builder
    public static class Service {
        @NonNull
        protected String name;

        @NonNull
        protected Boolean ok;

        // TODO: add response time parser
        // @NonNull
        // protected Integer responseTime;
    }

    @Builder.Default
    protected List<Service> services = new ArrayList<>();
}
