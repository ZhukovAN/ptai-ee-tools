package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor.PtaiSastTemplateDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings.PtaiSastSettings;
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
public class PtaiSastTemplate implements Describable<PtaiSastTemplate>, Cloneable, Serializable {
    @Getter
    private String templateName;
    @DataBoundSetter
    public void setTemplateName(final String templateName) {
        this.templateName = templateName;
    }

    @Getter
    private String templateBody;
    @DataBoundSetter
    public void setTemplateBody(final String templateBody) {
        this.templateBody = templateBody;
    }

    @Getter
    private PtaiSastSettings sastSettings;
    @DataBoundSetter
    public void setSastSettings(final PtaiSastSettings sastSettings) {
        this.sastSettings = sastSettings;
    }

    public PtaiSastTemplateDescriptor getDescriptor() {
        return Jenkins.getInstance().getDescriptorByType(PtaiSastTemplateDescriptor.class);
    }

    @DataBoundConstructor
    public PtaiSastTemplate(final String templateName, final String templateBody, final PtaiSastSettings sastSettings) {
        this.templateName = templateName;
        this.templateBody = templateBody;
        this.sastSettings = sastSettings;
    }
}
