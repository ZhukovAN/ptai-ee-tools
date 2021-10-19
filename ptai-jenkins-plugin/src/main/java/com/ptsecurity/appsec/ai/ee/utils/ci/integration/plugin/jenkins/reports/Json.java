package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class Json extends BaseReport {
    @Getter
    private final String json;

    @DataBoundConstructor
    public Json(final String json) {
        this.json = json;
    }

    @Symbol("json")
    @Extension
    public static class JsonDescriptor extends BaseReportDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_result_reporting_json_label();
        }
    }
}
