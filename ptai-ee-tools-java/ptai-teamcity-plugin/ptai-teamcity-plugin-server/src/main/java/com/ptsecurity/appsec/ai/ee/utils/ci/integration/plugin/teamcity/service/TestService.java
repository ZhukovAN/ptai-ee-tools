package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.controllers.XmlResponseUtil;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.util.StringUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.http.HttpStatus;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentStatus.FAILURE;
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

    private static final UrlValidator urlValidator = new UrlValidator(new String[] {"http","https"}, UrlValidator.ALLOW_LOCAL_URLS);

    private final static String PREFIX = "prop:";
    private final static String ENCRYPTED = "encrypted:";

    public static String getProperty(@NotNull HttpServletRequest request, @NotNull String name) {
        return StringUtil.emptyIfNull(request.getParameter(PREFIX + name));
    }

    public static String getEncryptedProperty(@NotNull HttpServletRequest request, @NotNull String name) {
        String propertyName = PREFIX + ENCRYPTED + name;
        return StringUtil.emptyIfNull(request.getParameter(propertyName));
    }

    public static ActionErrors validateConnectionSettings(BasePropertiesBean bean) {
        // JavaScript handlers are named as on[Error ID]Error like "onEmptyUrlError"
        ActionErrors res = new ActionErrors();
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(URL)))
            res.addError(URL, MESSAGE_URL_EMPTY);
        else if (!urlValidator.isValid(bean.getProperties().get(URL)))
            res.addError(URL, MESSAGE_URL_NOT_VALID);
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(USER)))
            res.addError(USER, MESSAGE_USERNAME_EMPTY);
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(TOKEN)))
            res.addError(TOKEN, MESSAGE_TOKEN_EMPTY);
        if (StringUtils.isNotEmpty(bean.getProperties().get(CERTIFICATES))) {
            try {
                List<X509Certificate> certs = new Client().checkCaCerts(emptyIfNull(bean.getProperties().get(CERTIFICATES)));
                if (certs.isEmpty())
                    res.addError(CERTIFICATES, "Trusted certificates not found");
            } catch (Exception e) {
                BaseClientException base = new BaseClientException("Invalid trusted certificates", e);
                Loggers.SERVER.info(base);
                res.addError(CERTIFICATES, base.getMessage());
            }
        }
        return res;
    }

    private static Client createClient(
            @NotNull String url, @NotNull String user,
            @NotNull String token, @Nullable String trustedCertificates) {
        Client client = new Client();
        client.setUrl(url);
        client.setClientId(CLIENT_ID);
        client.setClientSecret(CLIENT_SECRET);
        client.setUserName(user);
        client.setPassword(token);
        if (StringUtils.isNotEmpty(trustedCertificates))
            client.setCaCertsPem(trustedCertificates);
        return client;
    }

    private static String testConnection(
            @NotNull Client client,
            @NotNull String url, @NotNull String user,
            @NotNull String token, @Nullable String trustedCertificates, List<String> details) {
        try {
            client.init();
            BuildInfo buildInfo = client.getPublicApi().getBuildInfo();
            String buildInfoText = "PT AI EE integration server build info: " + buildInfo.getName() + ".v" + buildInfo.getVersion() + " from " + buildInfo.getDate();
            details.add(buildInfoText);
            Loggers.SERVER.info(buildInfoText);

            ComponentsStatus statuses = client.getDiagnosticApi().getStatus();
            String statusText = "PT AI EE components status: PT AI: " + statuses.getPtai() + "; Embedded: " + statuses.getEmbedded();
            details.add(statusText);
            Loggers.SERVER.info(statusText);
            return (statuses.getPtai().equals(FAILURE) || statuses.getEmbedded().equals(FAILURE)) ? "FAILED" : "SUCCESS";
        } catch (Exception e) {
            BaseClientException base = new BaseClientException("PT AI connection test failed", e);
            Loggers.SERVER.info(base);
            details.add(base.getMessage());
            return "FAILED";
        }
    }

    private static String testConnection(
            @NotNull String url, @NotNull String user,
            @NotNull String token, @Nullable String trustedCertificates, List<String> details) {
        Client client = createClient(url, user, token, trustedCertificates);
        return testConnection(client, url, user, token, trustedCertificates, details);
    }

    private static String testConnection(BasePropertiesBean bean, List<String> details) {
        return testConnection(
                bean.getProperties().get(URL),
                bean.getProperties().get(USER), bean.getProperties().get(TOKEN),
                bean.getProperties().get(CERTIFICATES),
                details);
    }

    private static String testConnection(Client client, BasePropertiesBean bean, List<String> details) {
        return testConnection(
                client,
                bean.getProperties().get(URL),
                bean.getProperties().get(USER), bean.getProperties().get(TOKEN),
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
        Element detailsElement = new Element("testConnectionDetails");
        xmlResponse.addContent(detailsElement);
        for (String line : details) {
            final Element element = new Element("line");
            detailsElement.addContent(element);
            element.addContent(line);
        }
        // Add final result
        XmlResponseUtil.writeTestResult(xmlResponse, res);
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
                    JsonSettingsVerifier.verify(bean.getProperties().get(JSON_SETTINGS));
                } catch (PtaiClientException e) {
                    res.addError(JSON_SETTINGS, MESSAGE_JSON_SETTINGS_INVALID);
                }
            try {
                JsonPolicyVerifier.verify(bean.getProperties().get(JSON_POLICY));
            } catch (PtaiClientException e) {
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
        String res = "FAILED";
        do {
            Client client = createClient(
                    bean.getProperties().get(URL),
                    bean.getProperties().get(USER), bean.getProperties().get(TOKEN),
                    bean.getProperties().get(CERTIFICATES));
            res = testConnection(client, bean, details);
            if (!"SUCCESS".equalsIgnoreCase(res)) break;
            // If project name is defined it must exist as we have no AST settings defined elsewhere
            if (AST_SETTINGS_UI.equals(bean.getProperties().get(AST_SETTINGS))) {
                try {
                    UUID projectId = client.getDiagnosticApi().getProjectId(bean.getProperties().get(PROJECT_NAME));
                    details.add("Project " + bean.getProperties().get(PROJECT_NAME) + " found, ID = " + projectId.toString());
                } catch (ApiException e) {
                    if (HttpStatus.SC_NOT_FOUND == e.getCode())
                        details.add("Project " + bean.getProperties().get(PROJECT_NAME) + " not found");
                    res = "FAILED";
                    break;
                }
            } else {
                ScanSettings settingsJson = JsonSettingsVerifier.verify(bean.getProperties().get(JSON_SETTINGS));
                details.add("JSON settings are verified, project name is " + settingsJson.getProjectName());
                Policy policyJson[] = JsonPolicyVerifier.verify(bean.getProperties().get(JSON_POLICY));
                details.add("JSON policy is verified, number of rule sets is " + policyJson.length);
            }
        } while (false);

        // Add details
        Element detailsElement = new Element("testConnectionDetails");
        xmlResponse.addContent(detailsElement);
        for (String line : details) {
            final Element element = new Element("line");
            detailsElement.addContent(element);
            element.addContent(line);
        }
        // Add final result
        XmlResponseUtil.writeTestResult(xmlResponse, res);
    }

}
