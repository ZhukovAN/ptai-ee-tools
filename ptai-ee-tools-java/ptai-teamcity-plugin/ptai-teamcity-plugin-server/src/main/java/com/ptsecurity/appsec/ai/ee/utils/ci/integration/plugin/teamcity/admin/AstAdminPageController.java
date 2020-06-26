package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;

import static com.intellij.openapi.util.text.StringUtil.getPropertyName;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Messages.*;
import jetbrains.buildServer.controllers.*;
import jetbrains.buildServer.log.Loggers;

import static com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentStatus.FAILURE;
import static jetbrains.buildServer.util.StringUtil.emptyIfNull;

import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.util.StringUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.UrlValidator;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AstAdminPageController extends BaseFormXmlController {
    private static final String ERROR_SUFFIX = "Error";

    private final AstAdminSettings settings;

    public AstAdminPageController(
            @NotNull WebControllerManager manager,
            AstAdminSettings settings,
            PluginDescriptor descriptor) {
        this.settings = settings;
        manager.registerController(ADMIN_CONTROLLER_PATH, this);
    }

    @Override
    protected ModelAndView doGet(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        return null;
    }

    private final static String PREFIX = "prop:";
    private final static String ENCRYPTED = "encrypted:";

    private static String getProperty(@NotNull HttpServletRequest request, @NotNull String name) {
        return StringUtil.emptyIfNull(request.getParameter(PREFIX + name));
    }

    private static String getEncryptedProperty(@NotNull HttpServletRequest request, @NotNull String name) {
        String propertyName = PREFIX + ENCRYPTED + name;
        return StringUtil.emptyIfNull(request.getParameter(propertyName));
    }

    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xmlResponse) {
        if (PublicKeyUtil.isPublicKeyExpired(request)) {
            PublicKeyUtil.writePublicKeyExpiredError(xmlResponse);
            return;
        }

        BasePropertiesBean bean = new BasePropertiesBean(null);
        String serverSettings = getProperty(request, SERVER_SETTINGS);
        if (SERVER_SETTINGS_GLOBAL.equalsIgnoreCase(serverSettings)) {
            bean.setProperty(URL, settings.getValue(URL));
            bean.setProperty(USER, settings.getValue(USER));
            bean.setProperty(TOKEN, settings.getValue(TOKEN));
            bean.setProperty(CERTIFICATES, settings.getValue(CERTIFICATES));
        } else {
            bean.setProperty(URL, getProperty(request, URL));
            bean.setProperty(USER, getProperty(request, USER));
            String token = RSACipher.decryptWebRequestData(getEncryptedProperty(request, TOKEN));
            bean.setProperty(TOKEN, token);
            bean.setProperty(CERTIFICATES, getProperty(request, CERTIFICATES));
        }


        String submitMode = request.getParameter("mode");
        if ("modify".equalsIgnoreCase(submitMode))
            XmlResponseUtil.writeFormModifiedIfNeeded(xmlResponse, bean);
        else {
            // Check if settings passed as a subject to save or to test connection are correct
            ActionErrors errors = validate(bean);
            if (errors.hasErrors()) {
                writeErrors(xmlResponse, errors);
                return;
            }
            if ("test".equalsIgnoreCase(submitMode)) {
                List<String> details = new ArrayList<>();
                String res = testPtaiConnection(bean, details);
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
                // xmlResponse now contains:
                // <testConnectionResult> as a top-level connection test result like SUCCESS or FAILURE
                // <testConnectionDetails> -> (*) <line> as a detailed representation
            } else if (submitMode.equals("save")) {
                bean.getProperties().forEach(settings::setValue);
                try {
                    settings.saveConfig();
                } catch (IOException e) {
                    Loggers.SERVER.error("Failed to persist PT AI global configuration", e);
                }
                FormUtil.removeAllFromSession(request.getSession(), bean.getClass());
                writeRedirect(xmlResponse, request.getContextPath() + "/admin/admin.html?item=" + PLUGIN_NAME);
            }
        }
    }

    private static final String[] GENERIC_TLDS_PLUS = new String[] { "corp", "local" };

    static {
        DomainValidator.updateTLDOverride(DomainValidator.ArrayType.GENERIC_PLUS, GENERIC_TLDS_PLUS);
    }

    private static final UrlValidator urlValidator = new UrlValidator(new String[] {"http","https"}, UrlValidator.ALLOW_LOCAL_URLS);

    private ActionErrors validate(BasePropertiesBean bean) {
        // JavaScript handlers are named as on[Error ID]Error like "onEmptyUrlError"
        ActionErrors res = new ActionErrors();
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(URL)))
            res.addError("emptyUrl", MESSAGE_URL_EMPTY);
        else if (!urlValidator.isValid(bean.getProperties().get(URL)))
            res.addError("invalidUrl", MESSAGE_URL_NOT_VALID);
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(USER)))
            res.addError("emptyUser", MESSAGE_USERNAME_EMPTY);
        if (StringUtil.isEmptyOrSpaces(bean.getProperties().get(TOKEN)))
            res.addError("emptyToken", MESSAGE_TOKEN_EMPTY);
        if (StringUtils.isNotEmpty(bean.getProperties().get(CERTIFICATES))) {
            try {
                List<X509Certificate> certs = new Client().checkCaCerts(emptyIfNull(bean.getProperties().get(CERTIFICATES)));
                if (certs.isEmpty())
                    res.addError("emptyCertificates", "Trusted certificates not found");
            } catch (Exception e) {
                BaseClientException base = new BaseClientException("Invalid trusted certificates", e);
                Loggers.SERVER.info(base);
                res.addError("invalidCertificates", base.getMessage());
            }
        }
        return res;
    }

    public static String testPtaiConnection(
            @NotNull String url, @NotNull String user,
            @NotNull String token, @Nullable String trustedCertificates, List<String> details) {
        try {
            com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client client = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client();
            client.setUrl(url);
            client.setClientId(CLIENT_ID);
            client.setClientSecret(CLIENT_SECRET);
            client.setUserName(user);
            client.setPassword(token);
            if (StringUtils.isNotEmpty(trustedCertificates))
                client.setCaCertsPem(trustedCertificates);
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

    public static String testPtaiConnection(BasePropertiesBean bean, List<String> details) {
        return testPtaiConnection(
                bean.getProperties().get(URL),
                bean.getProperties().get(USER), bean.getProperties().get(TOKEN),
                bean.getProperties().get(CERTIFICATES),
                details);
    }
}
