package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import hudson.Extension;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class WorkModeAsync extends WorkMode {
    @DataBoundConstructor
    public WorkModeAsync() {}

    @Symbol("WorkModeAsync")
    @Extension
    public static class Descriptor extends WorkModeDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_workMode_async_displayName();
        }
    }
}
