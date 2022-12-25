package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v420.events;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString
public class ScanStartedEvent {
    protected UUID projectId;
    protected UUID scanResultId;
}
