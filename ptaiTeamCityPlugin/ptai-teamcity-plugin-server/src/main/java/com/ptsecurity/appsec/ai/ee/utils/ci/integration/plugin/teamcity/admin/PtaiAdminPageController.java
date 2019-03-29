package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.PtaiAdminConfig;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BaseFormXmlController;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.util.StringUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

public class PtaiAdminPageController extends BaseFormXmlController {
    public static final String INVALID = "invalid_";
    private final PtaiAdminConfig ptaiAdminConfig;

    public PtaiAdminPageController(@NotNull WebControllerManager manager,
                                   @NotNull PtaiAdminConfig ptaiAdminConfig,
                                   PluginDescriptor descriptor) {
        this.ptaiAdminConfig = ptaiAdminConfig;
        manager.registerController("/ptai/adminSettings.html", this);
    }

    @Override
    protected ModelAndView doGet(@NotNull HttpServletRequest httpServletRequest, @NotNull HttpServletResponse httpServletResponse) {
        return null;
    }

    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xmlResponse) {
        /*
        ActionErrors actionErrors = validateForm(request);
        if (actionErrors.hasErrors()) {
            actionErrors.serialize(xmlResponse);
            return;
        }
        */
        this.ptaiAdminConfig.setCaCertsPem(StringUtil.emptyIfNull(request.getParameter("caCertsPem")));
        this.ptaiAdminConfig.setJenkinsServerUrl(StringUtil.emptyIfNull(request.getParameter("jenkinsServerUrl")));
        this.ptaiAdminConfig.setJenkinsJobName(StringUtil.emptyIfNull(request.getParameter("jenkinsJobName")));
        this.ptaiAdminConfig.setJenkinsLogin(StringUtil.emptyIfNull(request.getParameter("jenkinsLogin")));
        this.ptaiAdminConfig.setJenkinsPassword(StringUtil.emptyIfNull(request.getParameter("jenkinsPassword")));

        this.ptaiAdminConfig.setPtaiServerUrl(StringUtil.emptyIfNull(request.getParameter("ptaiServerUrl")));
        this.ptaiAdminConfig.setPtaiKeyPem(StringUtil.emptyIfNull(request.getParameter("ptaiKeyPem")));
        this.ptaiAdminConfig.setPtaiKeyPemPassword(StringUtil.emptyIfNull(request.getParameter("ptaiKeyPemPassword")));

        try {
            this.ptaiAdminConfig.saveConfiguration();
        } catch (IOException e) {
            Loggers.SERVER.error("Failed to persist global configurations", e);
        }
        getOrCreateMessages(request).addMessage("settingsSaved", "Settings Saved Successfully");
    }

    private ActionErrors validateForm(HttpServletRequest request) {
        ActionErrors ret = new ActionErrors();
        String cxGlobalServerUrl = request.getParameter("cxGlobalServerUrl");
        if (StringUtil.isEmptyOrSpaces(cxGlobalServerUrl)) {
            ret.addError("invalid_cxGlobalServerUrl", "Server URL must not be empty");
        } else {
            try {
                URL url = new URL(cxGlobalServerUrl);
            } catch (MalformedURLException e) {
                ret.addError("invalid_cxGlobalServerUrl", "Server URL is not valid");
            }
        }
        if (StringUtil.isEmptyOrSpaces(request.getParameter("cxGlobalUsername"))) {
            ret.addError("invalid_cxGlobalUsername", "Username must not be empty");
        }
        if (StringUtil.isEmptyOrSpaces(request.getParameter("encryptedCxGlobalPassword"))) {
            ret.addError("invalid_cxGlobalPassword", "Password must not be empty");
        }
        validateNumericLargerThanZero("cxGlobalScanTimeoutInMinutes", "Scan timeout must be a number greater than zero", request, ret);
        if ("true".equals(request.getParameter("cxGlobalIsSynchronous"))) {
            if ("true".equals(request.getParameter("cxGlobalThresholdEnabled"))) {
                validateNumeric("cxGlobalHighThreshold", "Threshold must be 0 or greater, or leave blank for no thresholds", request, ret);
                validateNumeric("cxGlobalMediumThreshold", "Threshold must be 0 or greater, or leave blank for no thresholds", request, ret);
                validateNumeric("cxGlobalLowThreshold", "Threshold must be 0 or greater, or leave blank for no thresholds", request, ret);
            }
            if ("true".equals(request.getParameter("cxGlobalOsaThresholdEnabled"))) {
                validateNumeric("cxGlobalOsaHighThreshold", "Threshold must be 0 or greater, or leave blank for no thresholds", request, ret);
                validateNumeric("cxGlobalOsaMediumThreshold", "Threshold must be 0 or greater, or leave blank for no thresholds", request, ret);
                validateNumeric("cxGlobalOsaLowThreshold", "Threshold must be 0 or greater, or leave blank for no thresholds", request, ret);
            }
        }
        return ret;
    }

    private void validateNumeric(String parameterName, String errorMessage, HttpServletRequest request, ActionErrors errors) {
        String num = request.getParameter(parameterName);
        if (!StringUtil.isEmptyOrSpaces(num)) {
            if (!StringUtil.isNumber(num) || Integer.parseInt(num) < 0) {
                errors.addError(INVALID + parameterName, errorMessage);
            }
        }
    }

    private void validateNumericLargerThanZero(String parameterName, String errorMessage, HttpServletRequest request, ActionErrors errors) {
        String num = request.getParameter(parameterName);
        if (!StringUtil.isEmptyOrSpaces(num)) {
            if (!StringUtil.isNumber(num) || Integer.parseInt(num) <= 0) {
                errors.addError(INVALID + parameterName, errorMessage);
            }
        }
    }
}
