package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.events;

import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ScanResultModel;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ScanSettingsModel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ScanStartedEvent {
    protected ScanResultModel result;
    protected ScanSettingsModel settings;
}
