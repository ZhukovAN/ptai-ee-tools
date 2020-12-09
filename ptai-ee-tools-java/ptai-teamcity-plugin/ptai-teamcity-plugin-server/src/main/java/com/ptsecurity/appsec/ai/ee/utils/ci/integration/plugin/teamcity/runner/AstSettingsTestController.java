package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.TestService;
import jetbrains.buildServer.controllers.BaseFormXmlController;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.SERVER_SETTINGS_GLOBAL;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.TEST_CONTROLLER_PATH;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.TestService.getEncryptedProperty;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.TestService.getProperty;

public class AstSettingsTestController extends BaseFormXmlController {
    private final AstAdminSettings settings;

    public AstSettingsTestController(
            @NotNull WebControllerManager manager,
            AstAdminSettings settings,
            PluginDescriptor descriptor) {
        this.settings = settings;
        manager.registerController(TEST_CONTROLLER_PATH, this);
    }

    @Override
    protected ModelAndView doGet(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        return null;
    }

    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xmlResponse) {
        String mode = request.getParameter("mode");
        if ("test".equalsIgnoreCase(mode))
            testConnection(request, xmlResponse);
        else if ("check".equalsIgnoreCase(mode))
            checkSettings(request, xmlResponse);
    }

    protected void checkSettings(
            @NotNull HttpServletRequest request,
            @NotNull Element xmlResponse) {
        BasePropertiesBean bean = createConnectionSettingsBean(request);
        bean.setProperty(AST_SETTINGS, getProperty(request, AST_SETTINGS));
        bean.setProperty(PROJECT_NAME, getProperty(request, PROJECT_NAME));
        bean.setProperty(JSON_SETTINGS, getProperty(request, JSON_SETTINGS));
        bean.setProperty(JSON_POLICY, getProperty(request, JSON_POLICY));
        // Check if settings passed as a subject to save or to test connection are correct
        TestService.checkScanSettings(bean, xmlResponse);
    }

    protected void testConnection(
            @NotNull HttpServletRequest request,
            @NotNull Element xmlResponse) {
        BasePropertiesBean bean = createConnectionSettingsBean(request);
        TestService.testConnection(bean, xmlResponse);
    }

    protected BasePropertiesBean createConnectionSettingsBean(
            @NotNull HttpServletRequest request) {
        BasePropertiesBean bean = new BasePropertiesBean(null);
        String serverSettings = getProperty(request, SERVER_SETTINGS);
        if (SERVER_SETTINGS_GLOBAL.equalsIgnoreCase(serverSettings)) {
            // If global settings mode is selected - init bean with global field values
            bean.setProperty(URL, settings.getValue(URL));
            bean.setProperty(TOKEN, settings.getValue(TOKEN));
            bean.setProperty(CERTIFICATES, settings.getValue(CERTIFICATES));
            bean.setProperty(INSECURE, settings.getValue(INSECURE));
        } else {
            // If task-scope settings mode is selected - init bean from request
            bean.setProperty(URL, getProperty(request, URL));
            String token = RSACipher.decryptWebRequestData(getEncryptedProperty(request, TOKEN));
            bean.setProperty(TOKEN, token);
            bean.setProperty(CERTIFICATES, getProperty(request, CERTIFICATES));
            bean.setProperty(INSECURE, getProperty(request, INSECURE));
        }
        return bean;
    }
}
