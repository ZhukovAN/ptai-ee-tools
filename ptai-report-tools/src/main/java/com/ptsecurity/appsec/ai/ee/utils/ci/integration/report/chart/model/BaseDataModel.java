package com.ptsecurity.appsec.ai.ee.utils.ci.integration.report.chart.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue.Level;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BaseDataModel {
    public static int COLOR_HIGH = 0xf57962;
    public static int COLOR_MEDIUM = 0xf9ad37;
    public static int COLOR_LOW = 0x66cc99;
    public static int COLOR_POTENTIAL = 0x8cb5e1;
}
