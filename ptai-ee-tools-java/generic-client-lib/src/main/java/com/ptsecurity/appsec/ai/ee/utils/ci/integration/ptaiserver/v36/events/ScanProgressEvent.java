package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanProgress;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanResult;
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
