package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v42.events;

import com.ptsecurity.appsec.ai.ee.server.v42.notifications.model.ScanResult;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString
public class ScanCompleteEvent {
    protected ScanResult result;
    protected UUID id;
}
