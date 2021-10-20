package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CertificateHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static com.ptsecurity.appsec.ai.ee.ServerCheckResult.State.ERROR;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Messages.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
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

    @Getter
    @Setter
    public static class VerificationResults extends ArrayList<Pair<String, String>> {
        protected String result = SUCCESS;

        public void add(@NonNull final GenericException e) {
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

    public static VerificationResults checkConnectionSettings(@NonNull final PropertiesBean bean, boolean parametersOnly) {
        VerificationResults results = new VerificationResults();
        return checkConnectionSettings(bean, results, parametersOnly);
    }

    public static VerificationResults checkConnectionSettings(@NonNull final PropertiesBean bean, @NonNull VerificationResults results, boolean parametersOnly) {
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

    /**
     * Method creates generic properties bean with PT AI URL, token, CA certificates
     * and "insecure" flag from verification HTTP request
     * @param request PT AI server connection verification request. This
     *                request may contain global- or task-defined connection settings
     * @return Properties bean with PT AI server connection settings
     */
    public static PropertiesBean parseConnectionSettings(
            @NonNull final HttpServletRequest request,
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
            String token = RSACipher.decryptWebRequestData(PropertiesBean.getEncryptedProperty(request, TOKEN));
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
            @NonNull final HttpServletRequest request, final PropertiesBean bean) {
        PropertiesBean res = (null == bean) ? new PropertiesBean() : bean;
        res.fill(AST_SETTINGS, request);

        if (AST_SETTINGS_JSON.equals(res.get(AST_SETTINGS)))
            res.fill(JSON_SETTINGS, request).fill(JSON_POLICY, request);
        else if (AST_SETTINGS_UI.equals(res.get(AST_SETTINGS)))
            res.fill(PROJECT_NAME, request);
        res.fill(FAIL_IF_FAILED, request).fill(FAIL_IF_UNSTABLE, request)
                .fill(FULL_SCAN_MODE, request).fill(VERBOSE, request)
                .fill(INCLUDES, request).fill(REMOVE_PREFIX, request).fill(EXCLUDES, request)
                .fill(PATTERN_SEPARATOR, request).fill(USE_DEFAULT_EXCLUDES, request).fill(FLATTEN, request);
        res.fill(REPORTING_REPORT, request)
                .fill(REPORTING_REPORT_FILE, request)
                .fill(REPORTING_REPORT_TEMPLATE, request)
                .fill(REPORTING_REPORT_FORMAT, request)
                .fill(REPORTING_REPORT_LOCALE, request)
                .fill(REPORTING_REPORT_FILTER, request);
        res.fill(REPORTING_DATA, request)
                .fill(REPORTING_DATA_FILE, request)
                .fill(REPORTING_DATA_FORMAT, request)
                .fill(REPORTING_DATA_LOCALE, request)
                .fill(REPORTING_DATA_FILTER, request);
        res.fill(REPORTING_RAWDATA, request)
                .fill(REPORTING_RAWDATA_FILE, request);
        res.fill(REPORTING_JSON, request)
                .fill(REPORTING_JSON_SETTINGS, request);

        return res;
    }

    /**
     * Verify syntax of PT AI connection settings fields, i.e. check if
     * required fields aren't empty, URL syntax is ok, and validateJsonFilter certificates
     * @param bean PT AI server connection settings
     * @param results List of validation results
     */
    public static void validateConnectionSettings(
            @NonNull final PropertiesBean bean,
            @NonNull final VerificationResults results) {
        // JavaScript handlers are named as on[Error ID]Error like "onEmptyUrlError"

        // If global connection settings are defined in job settings there's
        // no need to generate error messages for every invalid field. Let's create
        // temp error list
        ActionErrors temp = new ActionErrors();

        if (bean.empty(URL))
            temp.addError(URL, Resources.i18n_ast_settings_server_url_message_empty());
        else if (Validator.validateUrl(bean.get(URL)).fail())
            temp.addError(URL, Resources.i18n_ast_settings_server_url_message_invalid());
        if (bean.empty(TOKEN))
            temp.addError(TOKEN, Resources.i18n_ast_settings_server_token_message_empty());
        if (!bean.empty(CERTIFICATES)) {
            try {
                List<X509Certificate> certs = CertificateHelper.readPem(emptyIfNull(bean.getProperties().get(CERTIFICATES)));
                if (certs.isEmpty())
                    temp.addError(CERTIFICATES, Resources.i18n_ast_settings_server_ca_pem_message_parse_empty());
            } catch (GenericException e) {
                temp.addError(CERTIFICATES, Resources.i18n_ast_result_reporting_json_message_file_parse_failed_details(e.getDetailedMessage()));
                log.warn(e.getDetailedMessage(), e);
            }
        }

        if (temp.hasErrors()) {
            if (bean.none(SERVER_SETTINGS) || bean.eq(SERVER_SETTINGS, SERVER_SETTINGS_LOCAL))
                temp.getErrors().forEach(e -> results.add(e.getId(), e.getMessage()));
            else
                results.add(SERVER_SETTINGS, MESSAGE_GLOBAL_SETTINGS_INVALID);
        }
    }

    /**
     * Verify syntax of PT AI AST job settings fields, i.e. check if
     * required fields aren't empty and JSON settings format is valid
     * @param bean PT AI AST job settings
     * @param results List of validation results
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
                } catch (GenericException e) {
                    results.add(JSON_SETTINGS, e.getDetailedMessage());
                    log.warn(e.getDetailedMessage(), e);
                }
            }

            try {
                JsonPolicyHelper.verify(bean.get(JSON_POLICY));
            } catch (GenericException e) {
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

        if (bean.isTrue(REPORTING_REPORT)) {
            if (bean.empty(REPORTING_REPORT_FILE))
                results.add(REPORTING_REPORT_FILE, Resources.i18n_ast_result_reporting_report_file_message_empty());
            if (bean.empty(REPORTING_REPORT_TEMPLATE))
                results.add(REPORTING_REPORT_TEMPLATE, Resources.i18n_ast_result_reporting_report_template_message_empty());
            if (!bean.empty(REPORTING_REPORT_FILTER)) {
                Validator.Result result = Validator.validateJsonIssuesFilter(bean.get(REPORTING_REPORT_FILTER));
                if (result.fail())
                    results.add(REPORTING_REPORT_FILTER, Resources.i18n_ast_result_reporting_report_filter_message_invalid_details(result.getDetails()));
            }
        }

        if (bean.isTrue(REPORTING_DATA)) {
            if (bean.empty(REPORTING_DATA_FILE))
                results.add(REPORTING_DATA_FILE, Resources.i18n_ast_result_reporting_data_file_message_empty());
            if (!bean.empty(REPORTING_DATA_FILTER)) {
                Validator.Result result = Validator.validateJsonIssuesFilter(bean.get(REPORTING_DATA_FILTER));
                if (result.fail())
                    results.add(REPORTING_DATA_FILTER, Resources.i18n_ast_result_reporting_data_filter_message_invalid_details(result.getDetails()));
            }
        }

        if (bean.isTrue(REPORTING_RAWDATA) && bean.empty(REPORTING_RAWDATA_FILE))
            results.add(REPORTING_RAWDATA_FILE, Resources.i18n_ast_result_reporting_rawdata_file_message_empty());

        if (bean.isTrue(REPORTING_JSON)) {
            if (bean.empty(REPORTING_JSON_SETTINGS))
                results.add(REPORTING_JSON_SETTINGS, Resources.i18n_ast_result_reporting_json_settings_message_empty());
            else {
                Validator.Result result = Validator.validateJsonReports(bean.get(REPORTING_JSON_SETTINGS));
                if (result.fail())
                    results.add(REPORTING_JSON_SETTINGS, Resources.i18n_ast_result_reporting_json_settings_message_invalid_details(result.getDetails()));
            }
        }
    }

    private static AbstractApiClient createApiClient(@NonNull PropertiesBean bean) {
        return Factory.client(ConnectionSettings.builder()
                .url(bean.get(URL))
                .credentials(TokenCredentials.builder().token(bean.get(TOKEN)).build())
                .caCertsPem(bean.get(CERTIFICATES))
                .insecure(bean.isTrue(INSECURE))
                .build());
    }

    /**
     * @param bean PT AI server connection settings bean
     * @param results Response that contains diagnostic messages
     *            that are related to connection check results
     */
    protected static void checkConnectionSettings(@NonNull PropertiesBean bean, @NonNull final VerificationResults results) {
        // Check connection
        try {
            AbstractApiClient client = createApiClient(bean);
            ServerCheckResult res = new Factory().checkServerTasks(client).check();
            res.stream().forEach(r -> results.add(r));
            log.info(res.text());
            results.setResult(res.getState().equals(ERROR) ? FAILURE : SUCCESS);
        } catch (GenericException e) {
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
        try {
            AbstractApiClient client = createApiClient(bean);
            // Check if project exists
            if (bean.eq(AST_SETTINGS, AST_SETTINGS_UI)) {
                UUID projectId = new Factory().projectTasks(client).searchProject(bean.get(PROJECT_NAME));
                if (null != projectId)
                    results.add("Project " + bean.get(PROJECT_NAME) + " found, ID = " + projectId.toString());
                else {
                    results.add("Project " + bean.get(PROJECT_NAME) + " not found");
                    results.failure();
                }
            } else {
                AiProjScanSettings settingsJson = JsonSettingsHelper.verify(bean.getProperties().get(JSON_SETTINGS));
                results.add("JSON settings are verified, project name is " + settingsJson.getProjectName());
                Policy[] policyJson = JsonPolicyHelper.verify(bean.getProperties().get(JSON_POLICY));
                results.add("JSON policy is verified, number of rule sets is " + policyJson.length);
            }
            // Check reporting settings
            Reports reports = bean.convert();
            reports = ReportUtils.validate(reports);
            new Factory().reportsTasks(client).check(reports);
        } catch (GenericException e) {
            log.warn(e.getDetailedMessage(), e);
            results.add(e);
        }
    }
}
