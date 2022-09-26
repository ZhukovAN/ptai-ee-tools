package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.events;

import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ScanProgressModel;
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
    protected UUID Id;
}
