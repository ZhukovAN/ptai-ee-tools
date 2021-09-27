package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.BaseReport;
import hudson.Extension;
import hudson.util.ListBoxModel;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.jvnet.localizer.LocaleProvider;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.ArrayList;
import java.util.Locale;

@ToString
public class WorkModeSync extends WorkMode {
    public enum OnAstError {
        NONE, FAIL, UNSTABLE
    }
    @Extension
    public static final WorkModeDescriptor DESCRIPTOR = new Descriptor();

    @Getter
    private final OnAstError onAstFailed;

    @Getter
    private final OnAstError onAstUnstable;

    @Getter
    private ArrayList<BaseReport> reports;

    public final void setReports(final ArrayList<BaseReport> reports) {
        if (reports == null)
            this.reports = new ArrayList<>();
        else
            this.reports = reports;
    }

    @DataBoundConstructor
    public WorkModeSync(
            @NonNull final OnAstError onAstFailed,
            @NonNull final OnAstError onAstUnstable,
            final ArrayList<BaseReport> reports) {
        this.onAstFailed = onAstFailed;
        this.onAstUnstable = onAstUnstable;
        setReports(reports);
    }

    @Symbol("WorkModeSync")
    public static class Descriptor extends WorkModeDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_label();
        }

        public ListBoxModel doFillOnAstFailedItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_ast_settings_mode_synchronous_onastfailed_none(), OnAstError.NONE.name());
            model.add(Resources.i18n_ast_settings_mode_synchronous_onastfailed_fail(), OnAstError.FAIL.name());
            model.add(Resources.i18n_ast_settings_mode_synchronous_onastfailed_unstable(), OnAstError.UNSTABLE.name());
            return model;
        }

        public ListBoxModel doFillOnAstUnstableItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_ast_settings_mode_synchronous_onastunstable_none(), OnAstError.NONE.name());
            model.add(Resources.i18n_ast_settings_mode_synchronous_onastunstable_fail(), OnAstError.FAIL.name());
            model.add(Resources.i18n_ast_settings_mode_synchronous_onastunstable_unstable(), OnAstError.UNSTABLE.name());
            return model;
        }

        public static OnAstError getDefaultOnAstFailed() {
            return OnAstError.FAIL;
        }

        public static OnAstError getDefaultOnAstUnstable() {
            return OnAstError.NONE;
        }
    }

}
