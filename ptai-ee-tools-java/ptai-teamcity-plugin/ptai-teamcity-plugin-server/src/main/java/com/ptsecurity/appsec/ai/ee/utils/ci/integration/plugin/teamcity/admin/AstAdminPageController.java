package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Messages.*;
import jetbrains.buildServer.controllers.*;
import jetbrains.buildServer.log.Loggers;

import static com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentStatus.FAILURE;
import static jetbrains.buildServer.util.StringUtil.emptyIfNull;

import jetbrains.buildServer.util.StringUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
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
        manager.registerController(CONTROLLER_PATH, this);
    }

    @Override
    protected ModelAndView doGet(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        return null;
    }

    /*
    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xmlResponse) {
        if (PublicKeyUtil.isPublicKeyExpired(request)) {
            PublicKeyUtil.writePublicKeyExpiredError(xmlResponse);
            return;
        }

        ActionErrors actionErrors = validate(request);
        if (actionErrors.hasErrors()) {
            actionErrors.serialize(xmlResponse);
            return;
        }

        settings.setValue(Settings.GLOBAL_URL, request.getParameter(Settings.GLOBAL_URL));
        settings.setValue(Settings.GLOBAL_USER, request.getParameter(Settings.GLOBAL_USER));
        settings.setValue(Settings.GLOBAL_TOKEN, request.getParameter(Settings.GLOBAL_TOKEN));
        settings.setValue(Settings.GLOBAL_TRUSTED_CERTIFICATES, request.getParameter(Settings.GLOBAL_TRUSTED_CERTIFICATES));

        String pass = RSACipher.decryptWebRequestData(request.getParameter(Settings.GLOBAL_TOKEN));
        if (!EncryptUtil.isScrambled(pass)) {
            try {
                pass = EncryptUtil.scramble(pass);
            } catch (RuntimeException e) {
                pass = "";
            }
        }
        settings.setValue(Settings.GLOBAL_TOKEN, pass);

        try {
            settings.saveConfig();;
        } catch (IOException e) {
            Loggers.SERVER.error("Failed to persist global configurations", e);
        }
        getOrCreateMessages(request).addMessage("settingsSaved", Settings.MESSAGE_SAVE_SUCCESS);
    }
    */

    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xmlResponse) {
        if (PublicKeyUtil.isPublicKeyExpired(request)) {
            PublicKeyUtil.writePublicKeyExpiredError(xmlResponse);
            return;
        }

        AstAdminSettingsBean bean = new AstAdminSettingsBean(
                settings.getValue(GLOBAL_URL),
                settings.getValue(GLOBAL_USER),
                settings.getValue(GLOBAL_TOKEN),
                settings.getValue(GLOBAL_TRUSTED_CERTIFICATES));
        FormUtil.bindFromRequest(request, bean);

        String submitMode = request.getParameter("submitMode");
        if ("storeToSession".equalsIgnoreCase(submitMode))
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
            } else if (submitMode.equals("storeToFile")) {
                settings.setValue(GLOBAL_URL, bean.ptaiGlobalUrl);
                settings.setValue(GLOBAL_USER, bean.ptaiGlobalUser);
                settings.setValue(GLOBAL_TOKEN, bean.ptaiGlobalToken);
                settings.setValue(GLOBAL_TRUSTED_CERTIFICATES, bean.ptaiGlobalTrustedCertificates);
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

    private static final UrlValidator urlValidator = new UrlValidator(new String[] {"http","https"}, UrlValidator.ALLOW_LOCAL_URLS);

    private ActionErrors validate(AstAdminSettingsBean bean) {
        // JavaScript handlers are named as on[Error ID]Error like "onEmptyUrlError"
        ActionErrors res = new ActionErrors();
        if (StringUtil.isEmptyOrSpaces(bean.ptaiGlobalUrl))
            res.addError("emptyPtaiUrl", MESSAGE_URL_EMPTY);
        else if (!urlValidator.isValid(bean.ptaiGlobalUrl))
            res.addError("invalidPtaiUrl", MESSAGE_URL_NOT_VALID);
        if (StringUtil.isEmptyOrSpaces(bean.ptaiGlobalUser))
            res.addError("emptyPtaiUser", MESSAGE_USERNAME_EMPTY);
        if (StringUtil.isEmptyOrSpaces(bean.ptaiGlobalToken))
            res.addError("emptyPtaiToken", MESSAGE_TOKEN_EMPTY);

        if (StringUtils.isNotEmpty(bean.ptaiGlobalTrustedCertificates)) {
            try {
                List<X509Certificate> certs = new Client().checkCaCerts(emptyIfNull(bean.ptaiGlobalTrustedCertificates));
                if (certs.isEmpty())
                    res.addError("emptyTrustedCertificates", "Trusted certificates not found");
            } catch (Exception e) {
                BaseClientException base = new BaseClientException("Invalid trusted certificates", e);
                Loggers.SERVER.info(base);
                res.addError("invalidTrustedCertificates", base.getMessage());
            }
        }

        return res;
    }

    private String testPtaiConnection(AstAdminSettingsBean bean, List<String> details){
        try {
            com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client client = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client();
            client.setUrl(bean.ptaiGlobalUrl);
            client.setClientId(CLIENT_ID);
            client.setClientSecret(CLIENT_SECRET);
            client.setUserName(bean.ptaiGlobalUser);
            client.setPassword(bean.ptaiGlobalToken);
            if (StringUtils.isNotEmpty(bean.ptaiGlobalTrustedCertificates))
                client.setCaCertsPem(bean.ptaiGlobalTrustedCertificates);
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
}
