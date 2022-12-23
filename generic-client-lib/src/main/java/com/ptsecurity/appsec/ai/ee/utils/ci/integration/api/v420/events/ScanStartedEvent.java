package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v420.events;

import com.ptsecurity.appsec.ai.ee.server.v420.notifications.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v420.notifications.model.ScanSettings;
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
