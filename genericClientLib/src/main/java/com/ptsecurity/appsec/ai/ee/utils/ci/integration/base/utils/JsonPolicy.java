package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class JsonPolicy {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Scopes {
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Rules {
            public String Field;
            public String Value;
            public boolean IsRegex;
        }
        public Rules[] Rules;
    }
    public int CountToActualize;
    public Scopes[] Scopes;

}
