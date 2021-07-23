package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.server.api.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.UrlHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import hudson.util.FormValidation;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;

import java.util.regex.Pattern;

@Slf4j
public class Validator {
    public static boolean doCheckFieldNotEmpty(String value) {
        return !StringUtils.isEmpty(value);
    }

    private static final String[] GENERIC_TLDS_PLUS = new String[] { "corp", "local" };

    static {
        DomainValidator.updateTLDOverride(DomainValidator.ArrayType.GENERIC_PLUS, GENERIC_TLDS_PLUS);
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

    public static boolean doCheckFieldJsonSettings(String value) {
        return checkViaException(() -> JsonSettingsHelper.verify(value));
    }

    public static boolean doCheckFieldJsonPolicy(String value) {
        return checkViaException(() -> { if (doCheckFieldNotEmpty(value)) JsonPolicyHelper.verify(value); });
    }

    public static boolean doCheckFieldJsonIssuesFilter(String value) {
        return checkViaException(() -> Reports.validateJsonFilter(value));
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

    public static FormValidation doCheckFieldJsonPolicy(String value, String errorMessage) {
        return doCheckFieldJsonPolicy(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldJsonSettings(String value, String errorMessage) {
        return doCheckFieldJsonSettings(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation doCheckFieldJsonIssuesFilter(String value, String errorMessage) {
        return doCheckFieldJsonIssuesFilter(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
    }

    public static FormValidation error(Exception e) {
        // log.log(Level.FINEST, "FormValidation error", e);
        String caption = e.getMessage();
        if (StringUtils.isEmpty(caption))
            return FormValidation.error(e, Messages.validator_test_failed());
        else {
            Exception cause = e;
            if (e instanceof ApiException) cause = ((ApiException) e).getInner();
            return FormValidation.error(cause, Messages.validator_test_failed_details(caption));
        }
    }

    public static FormValidation error(@NonNull final String message, Exception e) {
        // log.log(Level.FINEST, "FormValidation error", e);
        Exception cause = e;
        if (e instanceof ApiException) cause = ((ApiException) e).getInner();
        return FormValidation.error(cause, Messages.validator_test_failed_details(message));
    }

    public static FormValidation error(String message) {
        return FormValidation.error(message);
    }
}
