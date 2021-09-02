package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.events;

import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ScanSettings;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ScanStartedEvent {
    protected ScanResult result;
    protected V36ScanSettings settings;
}
