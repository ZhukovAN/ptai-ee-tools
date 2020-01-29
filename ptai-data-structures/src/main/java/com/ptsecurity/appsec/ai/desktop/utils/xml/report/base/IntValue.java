package com.ptsecurity.appsec.ai.desktop.utils.xml.report.base;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter @Setter @ToString
public class IntValue {
    @JacksonXmlText
    private int value;
}
