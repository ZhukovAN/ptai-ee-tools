package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Policy {
    /**
     * Available AST policy assessment results
     */
    public enum State {
        /**
         * No policy assessment done
         */
        NONE,
        /**
         * AST results violate policy
         */
        REJECTED,
        /**
         * AST results fit policy
         */
        CONFIRMED
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Scopes {
        @Getter
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Rules {
            @JsonProperty("Field")
            protected String field;
            @JsonProperty("Value")
            protected String value;
            @JsonProperty("IsRegex")
            protected boolean regex;
        }
        @JsonProperty("Rules")
        protected Rules[] rules;
    }
    @JsonProperty("CountToActualize")
    protected int countToActualize;
    @JsonProperty("Scopes")
    protected Scopes[] scopes;
}
