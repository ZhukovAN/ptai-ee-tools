package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.events;

import com.ptsecurity.appsec.ai.ee.server.v40.projectmanagement.model.ScanProgress;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@ToString
public class ScanProgressEvent {
    protected UUID scanResultId;
    protected ScanProgress progress;
    protected UUID Id;
}
