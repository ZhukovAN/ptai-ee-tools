package com.ptsecurity.appsec.ai.ee.scan.settings.v420;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class AiProjScanSettings extends AbstractAiProjScanSettings {
    public enum BlackBoxScanScope {
        @JsonProperty("Folder")
        FOLDER,
        @JsonProperty("Domain")
        DOMAIN,
        @JsonProperty("Path")
        PATH
    }
    @JsonProperty("ScanScope")
    protected BlackBoxScanScope blackBoxScanScope;

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Authentication {
        @Getter
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Item {
            @JsonProperty("domain")
            protected String domain;

            @Getter
            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class Credentials {
                @JsonProperty("cookie")
                protected String cookie;

                @AllArgsConstructor
                public enum Type {
                    // 0 = Form, 1 = HTTP, 2 = None, 3 = Cookie
                    FORM(0),
                    HTTP(1),
                    NONE(2),
                    COOKIE(3);

                    @JsonValue
                    private final int type;
                }
                @JsonProperty("type")
                protected Type type;

                @Getter
                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class Login {
                    @JsonProperty("name")
                    protected String name;
                    @JsonProperty("value")
                    protected String value;
                    @JsonProperty("regexp")
                    protected String regexp;
                    @JsonProperty("is_regexp")
                    protected Boolean regexpUsed;
                }
                @JsonProperty("login")
                protected Login login;

                @Getter
                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class Password {
                    @JsonProperty("name")
                    protected String name;
                    @JsonProperty("value")
                    protected String value;
                    @JsonProperty("regexp")
                    protected String regexp;
                    @JsonProperty("is_regexp")
                    protected Boolean regexpUsed;
                }
                @JsonProperty("password")
                protected Password password;
                @JsonProperty("credentials_id")
                protected String id;
            }
            @JsonProperty("credentials")
            protected Credentials credentials;
            @JsonProperty("test_url")
            protected String testUrl;
            @JsonProperty("form_url")
            protected String formUrl;
            @JsonProperty("form_xpath")
            protected String formXPath;
            @JsonProperty("regexp_of_success")
            protected String regexpOfSuccess;
        }
        @JsonProperty("auth_item")
        protected Item item;
    }
    @JsonProperty("Authentication")
    protected Authentication authentication;
    @JsonProperty("AutocheckAuthentication")
    protected Authentication autocheckAuthentication;

    @JsonProperty("UseSecurityPolicies")
    protected Boolean isUseSecurityPolicies;
    @JsonProperty("UserPackagePrefixes")
    protected String userPackagePrefixes;
    @JsonProperty("UseSastRules")
    protected Boolean isUseSastRules;

    public AiProjScanSettings fix() {
        super.fix();
        return this;
    }
}
