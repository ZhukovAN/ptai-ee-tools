package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.PtaiAdminSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import jetbrains.buildServer.controllers.*;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import static jetbrains.buildServer.util.StringUtil.emptyIfNull;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.jdom.Content;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class PtaiAdminSettingsPageController extends BaseFormXmlController {
    public static final String INVALID = "invalid_";
    private final PtaiAdminSettings ptaiAdminSettings;

    public PtaiAdminSettingsPageController(@NotNull WebControllerManager manager,
                                           @NotNull PtaiAdminSettings ptaiAdminSettings,
                                           PluginDescriptor descriptor) {
        this.ptaiAdminSettings = ptaiAdminSettings;
        manager.registerController("/ptai/adminSettings.html", this);
    }

    @Override
    protected ModelAndView doGet(@NotNull HttpServletRequest httpServletRequest, @NotNull HttpServletResponse httpServletResponse) {
        return null;
    }

    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xmlResponse) {
        if (PublicKeyUtil.isPublicKeyExpired(request)) {
            PublicKeyUtil.writePublicKeyExpiredError(xmlResponse);
            return;
        }
        PtaiAdminSettingsBean bean = new PtaiAdminSettingsBean(
                ptaiAdminSettings.getCaCertsPem(),
                ptaiAdminSettings.getPtaiServerUrl(),
                ptaiAdminSettings.getPtaiKeyPem(),
                ptaiAdminSettings.getPtaiKeyPemPassword(),
                ptaiAdminSettings.getJenkinsServerUrl(),
                ptaiAdminSettings.getJenkinsJobName(),
                ptaiAdminSettings.getJenkinsLogin(),
                ptaiAdminSettings.getJenkinsPassword());
        FormUtil.bindFromRequest(request, bean);

        String submitSettings = request.getParameter("submitSettings");
        if ("storeInSession".equalsIgnoreCase(submitSettings)) {
            XmlResponseUtil.writeFormModifiedIfNeeded(xmlResponse, bean);
        } else {
            ActionErrors errors = validate(bean);
            if (!errors.hasErrors()) {
                if ("testConnection".equalsIgnoreCase(submitSettings)) {
                    List<String> details = new ArrayList<>();
                    String testResult = handleTestNotification(bean, details);
                    // Add details
                    Element detailsElement = new Element("testConnectionDetails");
                    xmlResponse.addContent((Content)detailsElement);
                    for (String line : details) {
                        final Element element = new Element("line");
                        detailsElement.addContent((Content)element);
                        element.addContent(line);
                    }
                    // Add final result
                    XmlResponseUtil.writeTestResult(xmlResponse, testResult);
                } else if (submitSettings.equals("store")) {
                    try {
                        this.ptaiAdminSettings.setCaCertsPem(emptyIfNull(bean.getCaCertsPem()));
                        this.ptaiAdminSettings.setPtaiServerUrl(emptyIfNull(bean.getPtaiServerUrl()));
                        this.ptaiAdminSettings.setPtaiKeyPem(emptyIfNull(bean.getPtaiKeyPem()));
                        this.ptaiAdminSettings.setPtaiKeyPemPassword(emptyIfNull(bean.getPtaiKeyPemPassword()));
                        this.ptaiAdminSettings.setJenkinsServerUrl(emptyIfNull(bean.getJenkinsServerUrl()));
                        this.ptaiAdminSettings.setJenkinsJobName(emptyIfNull(bean.getJenkinsJobName()));
                        this.ptaiAdminSettings.setJenkinsLogin(emptyIfNull(bean.getJenkinsLogin()));
                        this.ptaiAdminSettings.setJenkinsPassword(emptyIfNull(bean.getJenkinsPassword()));
                        this.ptaiAdminSettings.saveConfiguration();
                    } catch (IOException e) {
                        Loggers.SERVER.error("Failed to persist global configurations", e);
                    }
                    FormUtil.removeAllFromSession(request.getSession(), bean.getClass());
                    writeRedirect(xmlResponse, request.getContextPath() + "/admin/admin.html?item=" + "ptsecurity");
                }
            }
            writeErrors(xmlResponse, errors);
        }
    }

    private ActionErrors validate(PtaiAdminSettingsBean bean) {
        ActionErrors errors = new ActionErrors();
        if (StringUtils.isEmpty(bean.ptaiServerUrl))
            errors.addError("ptaiServerUrl", "PTAI server URL must not be empty");
        if (!new UrlValidator(new String[] {"http", "https"}).isValid(emptyIfNull(bean.ptaiServerUrl)))
            errors.addError("ptaiServerUrl", "Invalid PTAI server URL");
        if (StringUtils.isEmpty(bean.caCertsPem))
            errors.addError("caCertsPem", "CA certificates must not be empty");
        try {
            List<X509Certificate> certs = new Client().checkCaCerts(emptyIfNull(bean.caCertsPem));
            if (certs.isEmpty())
                errors.addError("caCertsPem", "CA certificates chain must not be empty");
        } catch (BaseClientException e) {
            Loggers.SERVER.debug(e);
            errors.addError("caCertsPem", "CA certificates chain parse failed");
        }
        if (StringUtils.isEmpty(bean.ptaiKeyPem))
            errors.addError("ptaiKeyPem", "PTAI client certificates must not be empty");
        try {
            new Client().checkKey(bean.ptaiKeyPem, bean.ptaiKeyPemPassword);
        } catch (Exception e) {
            Loggers.SERVER.debug(e);
            errors.addError("ptaiKeyPem", "PTAI client certificate parse failed");
        }
        if (StringUtils.isEmpty(bean.jenkinsServerUrl))
            errors.addError("jenkinsServerUrl", "Jenkins server URL must not be empty");
        if (!new UrlValidator(new String[] {"http", "https"}).isValid(emptyIfNull(bean.jenkinsServerUrl)))
            errors.addError("jenkinsServerUrl", "Invalid Jenkins server URL");
        if (StringUtils.isEmpty(bean.jenkinsJobName))
            errors.addError("jenkinsJobName", "Jenkins server job name must not be empty");
        if (StringUtils.isEmpty(bean.jenkinsLogin))
            errors.addError("jenkinsLogin", "Jenkins user name must not be empty");

        return errors;
    }

    private String handleTestNotification(PtaiAdminSettingsBean bean){
        return "SUCCESS";
    }

    private String handleTestNotification(PtaiAdminSettingsBean bean, List<String> details){
        try {
            // Test CA cert chain
            Client client = new Client();
            List<X509Certificate> certs = client.checkCaCerts(bean.caCertsPem);
            details.add("CA certificate(s):");
            for (X509Certificate cert : certs)
                details.add(cert.getSubjectDN().getName());
            // Test client certificate
            KeyStore keyStore = client.checkKey(bean.ptaiKeyPem, bean.ptaiKeyPemPassword);
            X509Certificate cert = (X509Certificate)keyStore.getCertificate(keyStore.aliases().nextElement());
            details.add("Client certificate:");
            details.add(cert.getSubjectDN().getName());
            // Test PTAI server connection
            PtaiProject ptaiProject = new PtaiProject();
            ptaiProject.setVerbose(false);
            ptaiProject.setUrl(bean.ptaiServerUrl);
            ptaiProject.setKeyPem(bean.ptaiKeyPem);
            ptaiProject.setKeyPassword(bean.ptaiKeyPemPassword);
            ptaiProject.setCaCertsPem(bean.caCertsPem);
            String authToken = ptaiProject.init();
            details.add("PTAI authentication token starts with " + authToken.substring(0, 10));
            // Test Jenkins connection
            SastJob jenkinsClient = new SastJob();
            jenkinsClient.setUrl(bean.jenkinsServerUrl);
            jenkinsClient.setCaCertsPem(bean.caCertsPem);
            jenkinsClient.setJobName(bean.jenkinsJobName);
            if (StringUtils.isNotEmpty(bean.jenkinsLogin)) {
                jenkinsClient.setUserName(bean.jenkinsLogin);
                jenkinsClient.setPassword(bean.jenkinsPassword);
            }
            jenkinsClient.init();
            details.add("SAST job name is " + jenkinsClient.testSastJob());
            return "SUCCESS";
        } catch (BaseClientException | KeyStoreException e) {
            Loggers.SERVER.debug(e);
            details.add(e.getMessage());
            return "FAILED";
        }
    }

    private void validateCaCerts(String parameterName, String errorMessage, HttpServletRequest request, ActionErrors errors, List<String> messages) {
        try {
            String sastConfigCaCerts = request.getParameter(parameterName);
            if (StringUtils.isEmpty(sastConfigCaCerts)) throw new Exception("CA certificates must not be empty");
            List<X509Certificate> certs = new Client().checkCaCerts(sastConfigCaCerts);
            if (!certs.isEmpty()) {
                messages.add("CA certificate(s):");
                for (X509Certificate cert : certs)
                    messages.add(cert.getSubjectDN().getName());
            }
        } catch (Exception e) {
            Loggers.SERVER.debug(e);
            errors.addError(INVALID + parameterName, errorMessage);
        }
    }

    private void validateClientCertificate(HttpServletRequest request, ActionErrors errors, List<String> messages) {
        try {
            String ptaiKeyPem = request.getParameter("ptaiKeyPem");
            String ptaiKeyPemPassword = RSACipher.decryptWebRequestData(request.getParameter("ptaiKeyPemPassword"));
            if (EncryptUtil.isScrambled(ptaiKeyPemPassword)) {
                try {
                    ptaiKeyPemPassword = EncryptUtil.unscramble(ptaiKeyPemPassword);
                } catch (RuntimeException e) {
                    ptaiKeyPemPassword = "";
                }
            }
            KeyStore keyStore = new Client().checkKey(ptaiKeyPem, ptaiKeyPemPassword);
            X509Certificate cert = (X509Certificate)keyStore.getCertificate(keyStore.aliases().nextElement());
            messages.add("Client certificate:");
            messages.add(cert.getSubjectDN().getName());
        } catch (Exception e) {
            Loggers.SERVER.debug(e);
            // errors.addError(INVALID + parameterName, errorMessage);
        }

    }


}
