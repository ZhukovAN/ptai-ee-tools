package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor.PtaiSastConfigDescriptor;
import hudson.model.Describable;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import java.io.Serializable;


@EqualsAndHashCode
@ToString
public class PtaiSastConfig implements Describable<PtaiSastConfig>, Cloneable, Serializable {
    private static final Auth DEFAULT_AUTH = NoneAuth.INSTANCE;

    @Getter
    private String sastConfigName;
    @DataBoundSetter
    public void setSastConfigName(final String sastConfigName) {
        this.sastConfigName = sastConfigName;
    }

    @Getter
    private String sastConfigPtaiHostUrl;
    @DataBoundSetter
    public void setSastConfigPtaiHostUrl(final String sastConfigPtaiHostUrl) {
        this.sastConfigPtaiHostUrl = sastConfigPtaiHostUrl;
    }

    @Getter
    private String sastConfigPtaiCert;
    @DataBoundSetter
    public void setSastConfigPtaiCert(final String sastConfigPtaiCert) {
        this.sastConfigPtaiCert = sastConfigPtaiCert;
    }

    @Getter
    private String sastConfigPtaiCertPwd;
    @DataBoundSetter
    public void setSastConfigPtaiCertPwd(final String sastConfigPtaiCertPwd) {
        this.sastConfigPtaiCertPwd = sastConfigPtaiCertPwd;
    }

    @Getter
    private String sastConfigPtaiCaCerts;
    @DataBoundSetter
    public void setSastConfigPtaiCaCerts(final String sastConfigPtaiCaCerts) {
        this.sastConfigPtaiCaCerts = sastConfigPtaiCaCerts;
    }

    @Getter
    private String sastConfigJenkinsHostUrl;
    @DataBoundSetter
    public void setSastConfigJenkinsHostUrl(final String sastConfigJenkinsHostUrl) {
        this.sastConfigJenkinsHostUrl = sastConfigJenkinsHostUrl;
    }

    @Getter
    private String sastConfigJenkinsJobName;
    @DataBoundSetter
    public void setSastConfigJenkinsJobName(final String sastConfigJenkinsJobName) {
        this.sastConfigJenkinsJobName = sastConfigJenkinsJobName;
    }

    @Getter
    private Auth sastConfigJenkinsAuth;
    @DataBoundSetter
    public void setSastConfigJenkinsAuth(Auth theAuth) {
        this.sastConfigJenkinsAuth = (theAuth != null) ? theAuth : DEFAULT_AUTH;
    }

    @DataBoundConstructor
    public PtaiSastConfig(
            final String sastConfigName,
            final String sastConfigPtaiHostUrl, final String sastConfigPtaiCert, final String sastConfigPtaiCertPwd,
            final String sastConfigPtaiCaCerts,
            final String sastConfigJenkinsHostUrl, final String sastConfigJenkinsJobName, final Auth sastConfigJenkinsAuth) {
        this.sastConfigName = sastConfigName;
        this.sastConfigPtaiHostUrl = sastConfigPtaiHostUrl;
        this.sastConfigPtaiCert = sastConfigPtaiCert;
        this.sastConfigPtaiCertPwd = sastConfigPtaiCertPwd;
        this.sastConfigPtaiCaCerts = sastConfigPtaiCaCerts;
        this.sastConfigJenkinsHostUrl = sastConfigJenkinsHostUrl;
        this.sastConfigJenkinsJobName = sastConfigJenkinsJobName;
        this.sastConfigJenkinsAuth = sastConfigJenkinsAuth;
    }

    public PtaiSastConfigDescriptor getDescriptor() {
        return Jenkins.getInstance().getDescriptorByType(PtaiSastConfigDescriptor.class);
    }
}
