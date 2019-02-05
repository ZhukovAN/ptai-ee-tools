package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth;

import hudson.Extension;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class NoneAuth extends Auth {

    // private static final long serialVersionUID = -3128995428538415113L;

    @Extension
    public static final AuthDescriptor DESCRIPTOR = new NoneAuthDescriptor();

    public static final NoneAuth INSTANCE = new NoneAuth();


    @DataBoundConstructor
    public NoneAuth() {
    }
    /*
    @Override
    public void setAuthorizationHeader(URLConnection connection, BuildContext context) throws IOException {
        //TODO: Should remove potential existing header, but URLConnection does not provide means to do so.
        //      Setting null worked in the past, but is not valid with newer versions (of Jetty).
        //connection.setRequestProperty("Authorization", null);
    }
    */
    /*
    @Override
    public String toString() {
        return "'" + getDescriptor().getDisplayName() + "'";
    }

    @Override
    public String toString(Item item) {
        return toString();
    }
    */
    @Override
    public AuthDescriptor getDescriptor() {
        return DESCRIPTOR;
    }

    @Symbol("NoneAuth")
    public static class NoneAuthDescriptor extends AuthDescriptor {
        @Override
        public String getDisplayName() {
            return "No Authentication";
        }
    }
    /*
    @Override
    public int hashCode() {
        return "NoneAuth".hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return this.getClass().isInstance(obj);
    }
    */
}