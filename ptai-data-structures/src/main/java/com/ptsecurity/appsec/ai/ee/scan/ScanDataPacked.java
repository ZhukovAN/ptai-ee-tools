package com.ptsecurity.appsec.ai.ee.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public class ScanDataPacked {
    public enum Type {
        SCAN_BRIEF_DETAILED
    }

    protected Type type;

    protected String data;
}
