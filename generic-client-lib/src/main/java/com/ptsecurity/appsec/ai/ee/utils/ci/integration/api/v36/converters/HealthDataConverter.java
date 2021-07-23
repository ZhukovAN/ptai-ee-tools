package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters;

import com.ptsecurity.appsec.ai.ee.HealthData;
import com.ptsecurity.appsec.ai.ee.server.v36.systemmanagement.model.HealthCheck;
import com.ptsecurity.appsec.ai.ee.server.v36.systemmanagement.model.ServiceHealth;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Slf4j
public class HealthDataConverter {
    @NonNull
    public static HealthData convert(@NonNull final HealthCheck health) {
        List<HealthData.Service> services = new ArrayList<>();
        if (null == health.getServices() || health.getServices().isEmpty()) {
            log.warn("Health data services list is empty");
            log.trace(health.toString());
        } else {
            for (ServiceHealth serviceHealth : health.getServices()) {
                if (null == serviceHealth) continue;
                services.add(convert(serviceHealth));
            }
        }
        return HealthData.builder().services(services).build();
    }

    @NonNull
    public static HealthData.Service convert(@NonNull final ServiceHealth serviceHealth) {
        return HealthData.Service.builder()
                .name(Objects.requireNonNull(serviceHealth.getService(), "Health data service name is null"))
                .ok("Healthy".equalsIgnoreCase(Objects.requireNonNull(serviceHealth.getStatus(), "Health data service status is null")))
                .build();
    }
}
