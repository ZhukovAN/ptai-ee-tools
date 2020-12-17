package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.BaseAstController;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.AstSettingsService;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.PropertiesBean;
import jetbrains.buildServer.controllers.PublicKeyUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;

@Slf4j
public class AstSettingsPageController extends BaseAstController {
    /**
     * Globally defined PT AI server connection settings
     */
    private final AstAdminSettings settings;

    public AstSettingsPageController(
            @NotNull WebControllerManager manager,
            @NonNull AstAdminSettings settings,
            PluginDescriptor descriptor) {
        this.settings = settings;
        manager.registerController(AST_CONTROLLER_PATH, this);
    }

    @Override
    protected ModelAndView doGet(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        log.trace("Unsupported HTTP GET request type received by AST settings test controller");
        return null;
    }

    /**
     * Method processes "Check AST settings" command and verifies PT AI server
     * connection settings are valid, server is reachable, and AST params are valid too
     * @param request HTTP POST verification request from client
     * @param response
     * @param xml Verification result represented as XML data
     */
    @Override
    protected void doPost(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Element xml) {
        // Check if client-side public key not expired, this may happen if server was restarted
        if (PublicKeyUtil.isPublicKeyExpired(request)) {
            PublicKeyUtil.writePublicKeyExpiredError(xml);
            return;
        }
        // As we set up event handlers to send requests for any change in
        // the form, we need to process different modes separately

        String mode = request.getParameter("mode");
        log.trace("AST job settings test request with mode {}", mode);

        // Load request parameters into bean
        PropertiesBean bean = AstSettingsService.parseConnectionSettings(request, settings, null);
        AstSettingsService.parseAstSettings(request, bean);

        if (MODE_MODIFY.equals(mode)) {
            // Perform as-you-type field validation
            AstSettingsService.VerificationResults results = AstSettingsService.checkConnectionSettings(bean, true);
            results = AstSettingsService.checkAstSettings(bean, results, true);
            saveVerificationResults(xml, results);
        } else if (MODE_TEST.equals(mode)) {
            AstSettingsService.VerificationResults results = AstSettingsService.checkConnectionSettings(bean, false);
            boolean connectionSettingsErrors = results.isFailure();
            // If connection failed then perform only parameters syntax validation and skip AST check
            results = AstSettingsService.checkAstSettings(bean, results, connectionSettingsErrors);
            saveVerificationResults(xml, results);
        } else {
            // TODO Add ActionErrors for unsupported mode
            log.info("Ignoring unsuported mode {}", mode);
        }
    }
}
