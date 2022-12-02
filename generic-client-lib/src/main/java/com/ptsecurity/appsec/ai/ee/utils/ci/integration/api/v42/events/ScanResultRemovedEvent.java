package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v42.events;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString
public class ScanResultRemovedEvent {
    protected UUID scanResultId;
    protected UUID projectId;
    protected Boolean deleteGroup;
}
