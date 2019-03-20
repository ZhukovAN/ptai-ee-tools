package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;

public abstract class Auth extends AbstractDescribableImpl<Auth> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<Auth, AuthDescriptor> all = DescriptorExtensionList.createDescriptorList(Jenkins.get(), Auth.class);

    public static String generateAuthorizationHeaderValue(String authType, String user, String password /*,
                                                          BuildContext context*/) throws IOException {
        if (StringUtils.isEmpty(user)) throw new IllegalArgumentException("user null or empty");
        if (password == null) throw new IllegalArgumentException("password null"); // is empty password allowed for Basic Auth?
        String authTypeKey = getAuthType(authType);
        String tuple = user + ":" + password;
        // tuple = TokenMacroUtils.applyTokenMacroReplacements(tuple, context);
        byte[] encoded = Base64.encodeBase64(tuple.getBytes(StandardCharsets.UTF_8));
        return authTypeKey + " " + new String(encoded, StandardCharsets.UTF_8);
    }

    private static String getAuthType(String authType) {
        if ("Basic".equalsIgnoreCase(authType)) return "Basic";
        throw new IllegalArgumentException("AuthType wrong or not supported yet: " + authType);
    }

    public static abstract class AuthDescriptor extends Descriptor<Auth> {}

    // public abstract void setAuthorizationHeader(URLConnection connection, BuildContext context) throws IOException;
    @Override
    public Auth clone() throws CloneNotSupportedException {
        return (Auth)super.clone();
    }

}
