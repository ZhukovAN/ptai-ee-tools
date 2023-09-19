package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.UrlHelper;
import hudson.util.FormValidation;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Pattern;

import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ParseResult.Message.Type.ERROR;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V11;

@Slf4j
public class Validator {
    public static boolean doCheckFieldNotEmpty(String value) {
        return !StringUtils.isEmpty(value);
    }

    protected static boolean checkViaException(@NonNull final Runnable call) {
        try { call.run(); return true; } catch (Exception e) { return false; }
    }

    public static boolean doCheckFieldUrl(String value) {
        return UrlHelper.checkUrl(value);
    }

    public static boolean doCheckFieldInteger(Integer value) {
        return (null != value);
    }

    public static boolean doCheckFieldBetween(Integer value, int from, int to) {
        if (null == value) return false;
        return (from <= value) && (value <= to);
    }

    public static boolean doCheckFieldRegEx(String value) {
        return checkViaException(() -> Pattern.compile(value));
    }

    public static boolean doCheckFieldJsonIssuesFilter(String value) {
        return checkViaException(() -> ReportUtils.validateJsonFilter(value));
    }

    public static boolean doCheckFieldJsonReports(String value) {
        return checkViaException(() -> ReportUtils.validateJsonReports(value));
    }

    public static boolean doCheckFieldAdvancedSettings(String value) {
        return checkViaException(() -> AdvancedSettings.validate(value));
    }

    public static FormValidation doCheckFieldNotEmpty(String value, String errorMessage) {
        return doCheckFieldNotEmpty(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldInteger(Integer value, String errorMessage) {
        return doCheckFieldInteger(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldBetween(Integer value, int from, int to, String errorMessage) {
        return doCheckFieldBetween(value, from, to) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldUrl(String value, String errorMessage) {
        return doCheckFieldUrl(value) ? FormValidation.ok() : FormValidation.warning(errorMessage);
    }

    public static FormValidation doCheckFieldRegEx(String value, String errorMessage) {
        return doCheckFieldRegEx(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldJsonPolicy(String value) {
        try {
            if (!Validator.doCheckFieldNotEmpty(value))
                return FormValidation.ok(Resources.i18n_ast_settings_type_manual_json_policy_message_empty());

            Policy[] policy = JsonPolicyHelper.verify(value);
            if (null == policy || 0 == policy.length)
                return FormValidation.ok(Resources.i18n_ast_settings_type_manual_json_policy_message_empty());
            else
                return FormValidation.ok(Resources.i18n_ast_settings_type_manual_json_policy_message_success(policy.length));
        } catch (Exception e) {
            return Validator.error(e);
        }
    }

    public static FormValidation doCheckFieldJsonSettings(String value) {
        Collection<FormValidation> messages = new ArrayList<>();
        do {
            if (!doCheckFieldNotEmpty(value)) {
                messages.add(FormValidation.error(Resources.i18n_ast_settings_type_manual_json_settings_message_empty()));
                break;
            }

            UnifiedAiProjScanSettings.ParseResult parseResult = UnifiedAiProjScanSettings.parse(value);
            if (!parseResult.getMessages().isEmpty()) {
                log.trace("There are messages generated during parse");
                for (UnifiedAiProjScanSettings.ParseResult.Message message : parseResult.getMessages())
                    messages.add(message.getType().equals(ERROR)
                            ? FormValidation.error(message.getText())
                            : FormValidation.warning(message.getText()));
            }
            if (null == parseResult.getCause()) {
                if (V11 == parseResult.getSettings().getVersion())
                    messages.add(FormValidation.ok(
                            Resources.i18n_ast_settings_type_manual_json_settings_message_success(
                                    parseResult.getSettings().getProjectName(),
                                    parseResult.getSettings().getProgrammingLanguage().getValue())));
                else
                    messages.add(FormValidation.warning(Resources.i18n_ast_settings_type_manual_json_settings_message_deprecated()));
            } else
                messages.add(FormValidation.error(
                        parseResult.getCause(),
                        Resources.i18n_ast_settings_type_manual_json_settings_message_invalid()));
        } while (false);
        return FormValidation.aggregate(messages);
    }

    public static FormValidation doCheckFieldJsonIssuesFilter(String value, String errorMessage) {
        return doCheckFieldJsonIssuesFilter(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldJsonReports(String value, String errorMessage) {
        return doCheckFieldJsonReports(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldAdvancedSettings(String value, String errorMessage) {
        return doCheckFieldAdvancedSettings(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation error(Exception e) {
        // log.log(Level.FINEST, "FormValidation error", e);
        String caption = e.getMessage();
        if (StringUtils.isEmpty(caption))
            return FormValidation.error(e, Resources.i18n_ast_settings_test_message_failed());
        else {
            Throwable cause = e;
            if (e instanceof GenericException) cause = e.getCause();
            return FormValidation.error(cause, Resources.i18n_ast_settings_test_message_failed_details(caption));
        }
    }

    public static FormValidation error(@NonNull final String message, Exception e) {
        // log.log(Level.FINEST, "FormValidation error", e);
        Throwable cause = e;
        if (e instanceof GenericException) cause = e.getCause();
        return FormValidation.error(cause, Resources.i18n_ast_settings_test_message_failed_details(message));
    }

    public static FormValidation error(String message) {
        return FormValidation.error(message);
    }
}
