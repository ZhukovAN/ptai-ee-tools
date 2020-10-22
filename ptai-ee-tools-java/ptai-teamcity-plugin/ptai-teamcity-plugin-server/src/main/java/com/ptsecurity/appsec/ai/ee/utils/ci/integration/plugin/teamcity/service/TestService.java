package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service;

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
import jetbrains.buildServer.controllers.XmlResponseUtil;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.util.StringUtil;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Messages.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
import static jetbrains.buildServer.controllers.XmlResponseUtil.writeErrors;
import static jetbrains.buildServer.util.StringUtil.emptyIfNull;

public class TestService {
    private static final String[] GENERIC_TLDS_PLUS = new String[] { "corp", "local" };

    static {
        DomainValidator.updateTLDOverride(DomainValidator.ArrayType.GENERIC_PLUS, GENERIC_TLDS_PLUS);
    }

    private final static String PREFIX = "prop:";
    private final static String ENCRYPTED = "encrypted:";

    @NotNull
    public static String getProperty(@NotNull HttpServletRequest request, @NotNull String name) {
        return StringUtil.emptyIfNull(request.getParameter(PREFIX + name));
    }

    @NotNull
    public static String getEncryptedProperty(@NotNull HttpServletRequest request, @NotNull String name) {
        String propertyName = PREFIX + ENCRYPTED + name;
        return StringUtil.emptyIfNull(request.getParameter(propertyName));
    }

    public static ActionErrors validateConnectionSettings(@NotNull BasePropertiesBean bean) {
        // JavaScript handlers are named as on[Error ID]Error like "onEmptyUrlError"
        ActionErrors res = new ActionErrors();
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(URL)))
            res.addError(URL, MESSAGE_URL_EMPTY);
        else if (!UrlHelper.checkUrl(bean.getProperties().get(URL)))
            res.addError(URL, MESSAGE_URL_NOT_VALID);
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(TOKEN)))
            res.addError(TOKEN, MESSAGE_TOKEN_EMPTY);
        if (StringUtils.isNotEmpty(bean.getProperties().get(CERTIFICATES))) {
            try {
                List<X509Certificate> certs = CertificateHelper.readPem(emptyIfNull(bean.getProperties().get(CERTIFICATES)));
                if (certs.isEmpty())
                    res.addError(CERTIFICATES, "Trusted certificates not found");
            } catch (ApiException e) {
                Loggers.SERVER.info(e);
                res.addError(CERTIFICATES, e.getDetailedMessage());
            }
        }
        return res;
    }

    private static Utils createClient(
            @NotNull String url,
            @NotNull String token, @Nullable String trustedCertificates) {
        Utils utils = new Utils();
        utils.setUrl(url);
        utils.setToken(token);
        if (StringUtils.isNotEmpty(trustedCertificates))
            utils.setCaCertsPem(trustedCertificates);
        return utils;
    }

    private static String testConnection(
            @NotNull Utils client,
            @NotNull String url,
            @NotNull String token, @Nullable String trustedCertificates, List<String> details) {
        try {
            client.init();
            Utils.TestResult result = client.testConnection();
            details.add(result.text());
            Loggers.SERVER.info(result.text());

            return result.state().equals(Utils.TestResult.State.ERROR) ? "FAILED" : "SUCCESS";
        } catch (ApiException e) {
            Loggers.SERVER.info(e);
            details.add(e.getDetailedMessage());
            return "FAILED";
        }
    }

    private static String testConnection(
            @NotNull String url, @NotNull String token,
            @Nullable String trustedCertificates, List<String> details) {
        Utils client = createClient(url, token, trustedCertificates);
        return testConnection(client, url, token, trustedCertificates, details);
    }

    private static String testConnection(BasePropertiesBean bean, List<String> details) {
        return testConnection(
                bean.getProperties().get(URL),
                bean.getProperties().get(TOKEN),
                bean.getProperties().get(CERTIFICATES),
                details);
    }

    private static String testConnection(Utils client, BasePropertiesBean bean, List<String> details) {
        return testConnection(
                client,
                bean.getProperties().get(URL),
                bean.getProperties().get(TOKEN),
                bean.getProperties().get(CERTIFICATES),
                details);
    }

    public static void testConnection(@NotNull BasePropertiesBean bean,
                                      @NotNull Element xmlResponse) {
        // Check if settings passed as a subject to save or to test connection are correct
        ActionErrors errors = validateConnectionSettings(bean);
        if (errors.hasErrors()) {
            writeErrors(xmlResponse, errors);
            return;
        }
        List<String> details = new ArrayList<>();
        // Check connection
        String res = testConnection(bean, details);
        // Add details
        addDetails(xmlResponse, details);
        // Add final result
        XmlResponseUtil.writeTestResult(xmlResponse, res);
    }

    private static void addDetails(
            @NotNull final Element xmlResponse,
            @NonNull final List<String> details) {
        Element detailsElement = new Element("testConnectionDetails");
        xmlResponse.addContent(detailsElement);
        for (String line : details) {
            final Element element = new Element("line");
            detailsElement.addContent(element);
            element.addContent(line);
        }
    }

    public static ActionErrors validateScanSettings(BasePropertiesBean bean) {
        // JavaScript handlers are named as on[Error ID]Error like "onPtaiUrlError"
        final Map<String, String> properties = bean.getProperties();
        ActionErrors res = new ActionErrors();
        if (AST_SETTINGS_UI.equalsIgnoreCase(properties.get(AST_SETTINGS))) {
            if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(PROJECT_NAME)))
                res.addError(PROJECT_NAME, MESSAGE_PROJECT_NAME_EMPTY);
        } else {
            // Settings and policy are defined with JSON, let's validate them
            if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(JSON_SETTINGS)))
                res.addError(JSON_SETTINGS, MESSAGE_JSON_SETTINGS_EMPTY);
            else
                try {
                    JsonSettingsHelper.verify(bean.getProperties().get(JSON_SETTINGS));
                } catch (ApiException e) {
                    res.addError(JSON_SETTINGS, MESSAGE_JSON_SETTINGS_INVALID);
                }
            try {
                JsonPolicyHelper.verify(bean.getProperties().get(JSON_POLICY));
            } catch (ApiException e) {
                res.addError(JSON_POLICY, MESSAGE_JSON_POLICY_INVALID);
            }
        }
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(NODE_NAME)))
            res.addError(NODE_NAME, MESSAGE_NODE_NAME_EMPTY);
        return res;
    }

    public static void checkScanSettings(@NotNull BasePropertiesBean bean,
                                      @NotNull Element xmlResponse) {
        // Check if conection setings are set up
        ActionErrors errors = validateConnectionSettings(bean);
        if (errors.hasErrors()) {
            writeErrors(xmlResponse, errors);
            return;
        }
        // Check if settings passed as a subject to save or to test connection are correct
        errors = validateScanSettings(bean);
        if (errors.hasErrors()) {
            writeErrors(xmlResponse, errors);
            return;
        }

        List<String> details = new ArrayList<>();
        String res;
        do {
            Utils client = createClient(
                    bean.getProperties().get(URL),
                    bean.getProperties().get(TOKEN),
                    bean.getProperties().get(CERTIFICATES));
            res = testConnection(client, bean, details);
            if (!"SUCCESS".equalsIgnoreCase(res)) break;
            // If project name is defined it must exist as we have no AST settings defined elsewhere
            if (AST_SETTINGS_UI.equals(bean.getProperties().get(AST_SETTINGS))) {
                try {
                    UUID projectId = client.searchProject(bean.getProperties().get(PROJECT_NAME));
                    if (null != projectId)
                        details.add("Project " + bean.getProperties().get(PROJECT_NAME) + " found, ID = " + projectId.toString());
                    else {
                        details.add("Project " + bean.getProperties().get(PROJECT_NAME) + " not found");
                        res = "FAILED";
                        break;
                    }
                } catch (ApiException e) {
                    details.add("Project " + bean.getProperties().get(PROJECT_NAME) + " search failed: " + e.getMessage());
                    if (StringUtils.isNotEmpty(e.getDetails()))
                        details.add("Additional info: " + e.getDetails());
                    res = "FAILED";
                    break;
                }
            } else {
                ScanSettings settingsJson = JsonSettingsHelper.verify(bean.getProperties().get(JSON_SETTINGS));
                details.add("JSON settings are verified, project name is " + settingsJson.getProjectName());
                Policy[] policyJson = JsonPolicyHelper.verify(bean.getProperties().get(JSON_POLICY));
                details.add("JSON policy is verified, number of rule sets is " + policyJson.length);
            }
        } while (false);

        // Add details
        addDetails(xmlResponse, details);
        // Add final result
        XmlResponseUtil.writeTestResult(xmlResponse, res);
    }

}
