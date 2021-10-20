package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import hudson.Extension;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class WorkModeAsync extends WorkMode {
    @DataBoundConstructor
    public WorkModeAsync() {}

    @Extension
    @Symbol("workModeAsync")
    public static class Descriptor extends WorkModeDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_asynchronous_label();
        }
    }
}
