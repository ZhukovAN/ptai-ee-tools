package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v41.events;

import com.ptsecurity.appsec.ai.ee.server.v41.legacy.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v41.legacy.model.ScanSettings;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ScanStartedEvent {
    protected ScanResult result;
    protected ScanSettings settings;
}
