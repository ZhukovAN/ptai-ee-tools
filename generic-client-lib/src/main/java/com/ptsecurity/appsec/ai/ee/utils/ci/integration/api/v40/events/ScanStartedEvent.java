package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.events;

import com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.ScanSettings;
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
