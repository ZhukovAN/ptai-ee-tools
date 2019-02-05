package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth;

import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class TokenAuth extends Auth {
    @Getter
    private String userName;
    @DataBoundSetter
    public void setUserName(String theUserName) {
        this.userName = theUserName;
    }

    @Getter
    private String apiToken;
    @DataBoundSetter
    public void setApiToken(String theApiToken) {
        this.apiToken = theApiToken;
    }

    @DataBoundConstructor
    public TokenAuth() {}

    /*
    @DataBoundConstructor
    public TokenAuth(String theUserName, String theApiToken) {
        this.userName = theUserName;
        this.apiToken = theApiToken;
    }
    */

    @Symbol("TokenAuth")
    @Extension
    public static class TokenAuthDescriptor extends AuthDescriptor {
        @Override
        public String getDisplayName() {
            return "Token Authentication";
        }
    }
}
