package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v420.events;

import com.ptsecurity.appsec.ai.ee.server.v420.api.model.ScanProgressModel;
import com.ptsecurity.appsec.ai.ee.server.v420.api.model.ScanStatisticModel;
import com.ptsecurity.appsec.ai.ee.server.v420.notifications.model.ScanProgress;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString
public class ScanProgressEvent {
    protected UUID scanResultId;
    protected ScanProgressModel progress;
    protected ScanStatisticModel statistic;
    protected UUID projectId;
}
