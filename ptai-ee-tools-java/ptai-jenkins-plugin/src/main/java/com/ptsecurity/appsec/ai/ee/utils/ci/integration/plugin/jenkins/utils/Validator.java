package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import hudson.Util;
import hudson.util.FormValidation;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;

import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class Validator {
    public static boolean doCheckFieldNotEmpty(String value) {
        return !StringUtils.isEmpty(value);
    }

    public static boolean doCheckFieldUrl(String value) {
        UrlValidator urlValidator = new UrlValidator(new String[] {"http","https"});
        return urlValidator.isValid(value);
    }

    public static boolean doCheckFieldInteger(Integer value) {
        return (null != value);
    }

    public static boolean doCheckFieldBetween(Integer value, int from, int to) {
        if (null == value) return false;
        return (from <= value) && (value <= to);
    }

    public static boolean doCheckFieldRegEx(String value) {
        try {
            Pattern.compile(value);
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    public static boolean doCheckFieldJsonSettings(String value) {
        try {
            JsonSettingsVerifier.verify(value);
            return true;
        } catch (PtaiClientException e) {
            return false;
        }
    }

    public static boolean doCheckFieldJsonPolicy(String value) {
        try {
            if (doCheckFieldNotEmpty(value))
                JsonPolicyVerifier.verify(value);
            return true;
        } catch (PtaiClientException e) {
            return false;
        }
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
        return doCheckFieldUrl(value) ? FormValidation.ok() : FormValidation.error(errorMessage);
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

    public static FormValidation error(Exception e) {
        Throwable exception = e;
        String details = e.getMessage();
        if (e instanceof BaseClientException) {
            BaseClientException baseClientException = (BaseClientException)(e);
            exception = Optional.ofNullable(baseClientException.getInner()).orElse(baseClientException);
        }
        if (StringUtils.isEmpty(details))
            return FormValidation.error(exception, Messages.validator_test_failed());
        else
            return FormValidation.error(exception, Messages.validator_test_failed_details(details));
    }
}
