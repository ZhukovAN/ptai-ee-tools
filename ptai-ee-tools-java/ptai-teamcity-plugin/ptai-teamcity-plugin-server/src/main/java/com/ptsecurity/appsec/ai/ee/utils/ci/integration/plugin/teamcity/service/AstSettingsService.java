package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.CertificateHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.UrlHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Messages.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils.TestResult.State.ERROR;
import static jetbrains.buildServer.util.StringUtil.emptyIfNull;

/**
 * Class provides three groups of functions: parseXxxSettings - parses HTTP
 * request and creates bean with request field data,
 * validateXxxSettings - verifies syntax of fields in property bean and
 * checkXxxSettings - checks if field values are valid i.e. PT AI server
 * API may be called with these settings
 */
@Slf4j
public class AstSettingsService {

    /**
     * Method creates generic properties bean with PT AI URL, token, CA certificates
     * and "insecure" flag from verification HTTP request
     * @param request PT AI server connection verification request. This
     *                request may contain global- or task-defined connection settings
     * @return Properties bean with PT AI server connection settings
     */
    public static PropertiesBean parseConnectionSettings(
            @NotNull final HttpServletRequest request,
            @NonNull final AstAdminSettings settings,
            final PropertiesBean bean) {
        PropertiesBean res = (null == bean) ? new PropertiesBean() : bean;
        res.fill(SERVER_SETTINGS, request);

        if (SERVER_SETTINGS_GLOBAL.equals(res.get(SERVER_SETTINGS)))
            // If global settings mode is selected - init bean with global field values
            res.fill(URL, settings).fill(TOKEN, settings).fill(CERTIFICATES, settings).fill(INSECURE, settings);
        else if (SERVER_SETTINGS_LOCAL.equals(res.get(SERVER_SETTINGS))) {
            // If task-scope settings mode is selected - init bean from request
            res.fill(URL, request).fill(CERTIFICATES, request).fill(INSECURE, request);
            String token = RSACipher.decryptWebRequestData(res.getEncryptedProperty(request, TOKEN));
            res.setProperty(TOKEN, token);
        }
        return res;
    }

    /**
     * Method creates generic properties bean with AST job settings like JSON's,
     * project name etc. from verification HTTP request
     * @param request PT AI server job settings verification request
     * @return Properties bean with PT AI AST job settings
     */
    public static BasePropertiesBean parseAstSettings(
            @NotNull final HttpServletRequest request, final PropertiesBean bean) {
        PropertiesBean res = (null == bean) ? new PropertiesBean() : bean;
        res.fill(AST_SETTINGS, request);

        if (AST_SETTINGS_JSON.equals(res.get(AST_SETTINGS)))
            res.fill(JSON_SETTINGS, request).fill(JSON_POLICY, request);
        else if (AST_SETTINGS_UI.equals(res.get(AST_SETTINGS)))
            res.fill(PROJECT_NAME, request);
        res.fill(FAIL_IF_FAILED, request).fill(FAIL_IF_UNSTABLE, request)
                .fill(VERBOSE, request)
                .fill(INCLUDES, request).fill(REMOVE_PREFIX, request).fill(EXCLUDES, request)
                .fill(PATTERN_SEPARATOR, request).fill(USE_DEFAULT_EXCLUDES, request).fill(FLATTEN, request);
        return res;
    }

    /**
     * Verify syntax of PT AI connection settings fields, i.e. check if
     * required fields aren't empty, URL syntax is OK, and verify certificates
     * @param bean PT AI server connection settings
     * @param results List of validation results
     * @return List of validation errors
     */
    public static void validateConnectionSettings(
            @NotNull final PropertiesBean bean,
            @NonNull final VerificationResults results) {
        // JavaScript handlers are named as on[Error ID]Error like "onEmptyUrlError"

        // If global connection settings are defined in job settings there's
        // no need to generate error messages for every invalid field. Let's create
        // temp error list
        ActionErrors temp = new ActionErrors();

        if (bean.empty(URL))
            temp.addError(URL, MESSAGE_URL_EMPTY);
        else if (!UrlHelper.checkUrl(bean.get(URL)))
            temp.addError(URL, MESSAGE_URL_NOT_VALID);
        if (bean.empty(TOKEN))
            temp.addError(TOKEN, MESSAGE_TOKEN_EMPTY);
        if (!bean.empty(CERTIFICATES)) {
            try {
                List<X509Certificate> certs = CertificateHelper.readPem(emptyIfNull(bean.getProperties().get(CERTIFICATES)));
                if (certs.isEmpty())
                    temp.addError(CERTIFICATES, "Trusted certificates not found");
            } catch (ApiException e) {
                temp.addError(CERTIFICATES, e.getDetailedMessage());
                log.warn(e.getDetailedMessage(), e);
            }
        }

        if (temp.hasErrors()) {
            if (bean.none(SERVER_SETTINGS) || bean.eq(SERVER_SETTINGS, SERVER_SETTINGS_LOCAL))
                temp.getErrors().stream().forEach(e -> results.add(e.getId(), e.getMessage()));
            else
                results.add(SERVER_SETTINGS, MESSAGE_GLOBAL_SETTINGS_INVALID);
        }
    }

    /**
     * Verify syntax of PT AI AST job settings fields, i.e. check if
     * required fields aren't empty and JSON settings format is valid
     * @param bean PT AI AST job settings
     * @param results List of validation results
     * @return List of validation errors
     */
    protected static void validateAstSettings(@NonNull final PropertiesBean bean, @NonNull final VerificationResults results) {
        // JavaScript handlers are named as on[Error ID]Error like "onEmptyUrlError"
        if (bean.eq(AST_SETTINGS, AST_SETTINGS_UI) && bean.empty(PROJECT_NAME))
            results.add(PROJECT_NAME, MESSAGE_PROJECT_NAME_EMPTY);
        else if (bean.eq(AST_SETTINGS, AST_SETTINGS_JSON)) {
            // Settings and policy are defined with JSON, let's validate them
            if (bean.empty(JSON_SETTINGS))
                results.add(JSON_SETTINGS, MESSAGE_JSON_SETTINGS_EMPTY);
            else {
                try {
                    JsonSettingsHelper.verify(bean.get(JSON_SETTINGS));
                } catch (ApiException e) {
                    results.add(JSON_SETTINGS, e.getDetailedMessage());
                    log.warn(e.getDetailedMessage(), e);
                }
            }

            try {
                JsonPolicyHelper.verify(bean.get(JSON_POLICY));
            } catch (ApiException e) {
                results.add(JSON_POLICY, e.getDetailedMessage());
                log.warn(e.getDetailedMessage(), e);
            }
        }

        if (bean.empty(INCLUDES))
            results.add(INCLUDES, MESSAGE_INCLUDES_EMPTY);
        if (bean.empty(PATTERN_SEPARATOR))
            results.add(PATTERN_SEPARATOR, MESSAGE_PATTERN_SEPARATOR_EMPTY);
        else {
            try {
                Pattern.compile(bean.get(PATTERN_SEPARATOR));
            } catch (PatternSyntaxException e) {
                results.add(PATTERN_SEPARATOR, MESSAGE_PATTERN_SEPARATOR_INVALID);
            }
        }
    }

    private static Utils createUtils(@NotNull PropertiesBean bean) {
        Utils utils = new Utils();
        utils.setUrl(bean.get(URL));
        utils.setToken(bean.get(TOKEN));
        if (!bean.empty(CERTIFICATES))
            utils.setCaCertsPem(bean.get(CERTIFICATES));
        utils.setInsecure(bean.isTrue(INSECURE));
        utils.init();
        return utils;
    }

    /**
     * @param bean PT AI server connection settings bean
     * @param results Response that contains diagnostic messages
     *            that are related to connection check results
     */
    protected static void checkConnectionSettings(@NotNull PropertiesBean bean, @NonNull final VerificationResults results) {
        // Check connection
        try {
            Utils utils = createUtils(bean);
            Utils.TestResult result = utils.testConnection();
            result.stream().forEach(r -> results.add(r));
            log.info(result.text());
            results.setResult(result.state().equals(ERROR) ? FAILURE : SUCCESS);
        } catch (ApiException e) {
            log.warn(e.getDetailedMessage(), e);
            results.add(e);
        }
    }

    /**
     * @param bean PT AI AST job settings bean
     * @param results Response that contains diagnostic messages
     *            that are related to job check results
     */
    protected static void checkAstSettings(@NonNull final PropertiesBean bean, @NonNull final VerificationResults results) {
        // Check connection
        try {
            Utils utils = createUtils(bean);

            if (bean.eq(AST_SETTINGS, AST_SETTINGS_UI)) {
                UUID projectId = utils.searchProject(bean.get(PROJECT_NAME));
                if (null != projectId)
                    results.add("Project " + bean.get(PROJECT_NAME) + " found, ID = " + projectId.toString());
                else {
                    results.add("Project " + bean.get(PROJECT_NAME) + " not found");
                    results.failure();
                }
            } else {
                ScanSettings settingsJson = JsonSettingsHelper.verify(bean.getProperties().get(JSON_SETTINGS));
                results.add("JSON settings are verified, project name is " + settingsJson.getProjectName());
                Policy[] policyJson = JsonPolicyHelper.verify(bean.getProperties().get(JSON_POLICY));
                results.add("JSON policy is verified, number of rule sets is " + policyJson.length);
            }
        } catch (ApiException e) {
            log.warn(e.getDetailedMessage(), e);
            results.add(e);
        }
    }

    @Getter
    @Setter
    public static class VerificationResults extends ArrayList<Pair<String, String>> {
        protected String result = SUCCESS;

        public void add(@NonNull final ApiException e) {
            add(Pair.of(null, e.getDetailedMessage()));
            failure();
        }

        public void add(@NonNull final String details) {
            add(Pair.of(null, details));
        }

        public void add(@NonNull final String id, @NonNull final String error) {
            add(Pair.of(id, error));
            failure();
        }

        public void success() {
            result = SUCCESS;
        }

        public void failure() {
            result = FAILURE;
        }

        public boolean isSuccess() {
            return SUCCESS.equals(result);
        }

        public boolean isFailure() {
            return FAILURE.equals(result);
        }
    }

    public static VerificationResults checkConnectionSettings(@NotNull final PropertiesBean bean, boolean parametersOnly) {
        VerificationResults results = new VerificationResults();
        return checkConnectionSettings(bean, results, parametersOnly);
    }

    public static VerificationResults checkConnectionSettings(@NotNull final PropertiesBean bean, @NonNull VerificationResults results, boolean parametersOnly) {
        validateConnectionSettings(bean, results);
        if (!parametersOnly && results.isSuccess()) checkConnectionSettings(bean, results);
        return results;
    }

    public static VerificationResults checkAstSettings(@NonNull final PropertiesBean bean, boolean parametersOnly) {
        VerificationResults results = new VerificationResults();
        return checkAstSettings(bean, results, parametersOnly);
    }

    public static VerificationResults checkAstSettings(@NonNull final PropertiesBean bean, @NonNull VerificationResults results, boolean parametersOnly) {
        validateAstSettings(bean, results);
        if (!parametersOnly && results.isSuccess()) checkAstSettings(bean, results);
        return results;
    }
}
