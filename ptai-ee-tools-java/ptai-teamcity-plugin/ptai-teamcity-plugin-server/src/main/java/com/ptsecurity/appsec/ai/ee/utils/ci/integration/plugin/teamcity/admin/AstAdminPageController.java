package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.TestService;
import jetbrains.buildServer.controllers.*;
import jetbrains.buildServer.log.Loggers;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.TestService.getEncryptedProperty;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.TestService.getProperty;

import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AstAdminPageController extends BaseFormXmlController {
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

    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xmlResponse) {
        if (PublicKeyUtil.isPublicKeyExpired(request)) {
            PublicKeyUtil.writePublicKeyExpiredError(xmlResponse);
            return;
        }

        BasePropertiesBean bean = new BasePropertiesBean(null);
        bean.setProperty(URL, getProperty(request, URL));
        bean.setProperty(USER, getProperty(request, USER));
        bean.setProperty(TOKEN, RSACipher.decryptWebRequestData(getEncryptedProperty(request, TOKEN)));
        bean.setProperty(CERTIFICATES, getProperty(request, CERTIFICATES));

        String mode = request.getParameter("mode");
        if ("modify".equalsIgnoreCase(mode))
            XmlResponseUtil.writeFormModifiedIfNeeded(xmlResponse, bean);
        else {
            // Check if settings passed as a subject to save or to test connection are correct
            ActionErrors errors = TestService.validateConnectionSettings(bean);
            if (errors.hasErrors()) {
                writeErrors(xmlResponse, errors);
                return;
            }
            if ("test".equalsIgnoreCase(mode))
                TestService.testConnection(bean, xmlResponse);
            else if (mode.equals("save")) {
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
}
