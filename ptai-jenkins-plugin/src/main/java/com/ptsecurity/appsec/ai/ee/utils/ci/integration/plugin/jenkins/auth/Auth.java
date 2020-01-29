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

    public static abstract class AuthDescriptor extends Descriptor<Auth> {}

    @Override
    public Auth clone() throws CloneNotSupportedException {
        return (Auth)super.clone();
    }
}
