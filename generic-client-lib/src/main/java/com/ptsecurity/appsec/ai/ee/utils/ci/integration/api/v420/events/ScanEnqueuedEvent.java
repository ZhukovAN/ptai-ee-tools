package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v420.events;

import com.ptsecurity.appsec.ai.ee.server.v420.notifications.model.ScanResult;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString
public class ScanEnqueuedEvent {
    protected UUID scanResultId;
    protected UUID projectId;
}
