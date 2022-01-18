package com.ptsecurity.appsec.ai.ee.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class ScanDataPacked {
    public enum Type {
        SCAN_BRIEF_DETAILED
    }

    protected Type type;

    protected String data;
}
