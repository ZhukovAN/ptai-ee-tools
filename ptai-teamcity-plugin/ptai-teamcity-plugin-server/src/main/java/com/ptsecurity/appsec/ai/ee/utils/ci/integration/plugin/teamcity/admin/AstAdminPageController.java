package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.BaseAstController;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.AstSettingsService;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.PropertiesBean;
import jetbrains.buildServer.controllers.FormUtil;
import jetbrains.buildServer.controllers.PublicKeyUtil;
import jetbrains.buildServer.controllers.XmlResponseUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.jdom.Element;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.ADMIN_CONTROLLER_PATH;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

@Slf4j
public class AstAdminPageController extends BaseAstController {
    private final AstAdminSettings settings;

    public AstAdminPageController(
            @NonNull WebControllerManager manager,
            AstAdminSettings settings,
            PluginDescriptor descriptor) {
        this.settings = settings;
        manager.registerController(ADMIN_CONTROLLER_PATH, this);
    }

    @Override
    protected ModelAndView doGet(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response) {
        return null;
    }

    @Override
    protected void doPost(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Element xml) {
        if (PublicKeyUtil.isPublicKeyExpired(request)) {
            PublicKeyUtil.writePublicKeyExpiredError(xml);
            return;
        }

        PropertiesBean bean = new PropertiesBean().fill(URL, request).fill(CERTIFICATES, request).fill(INSECURE, request).fillSecret(TOKEN, request);

        String mode = request.getParameter("mode");
        if ("modify".equalsIgnoreCase(mode))
            XmlResponseUtil.writeFormModifiedIfNeeded(xml, bean);
        else {
            // Check if settings passed as a subject to save or to test connection are correct
            if ("test".equalsIgnoreCase(mode)) {
                AstSettingsService.VerificationResults results = AstSettingsService.checkConnectionSettings(bean, false);
                saveVerificationResults(xml, results);
            } else if (mode.equals("save")) {
                bean.getProperties().forEach(settings::setValue);
                try {
                    settings.saveConfig();
                } catch (IOException e) {
                    log.error("Failed to persist PT AI global configuration", e);
                }
                FormUtil.removeAllFromSession(request.getSession(), bean.getClass());
                // writeRedirect(xml, request.getContextPath() + "/admin/admin.html?item=" + PLUGIN_NAME);
                writeRedirect(xml, request.getContextPath() + "/admin/admin.html");
            }
        }
    }
}
