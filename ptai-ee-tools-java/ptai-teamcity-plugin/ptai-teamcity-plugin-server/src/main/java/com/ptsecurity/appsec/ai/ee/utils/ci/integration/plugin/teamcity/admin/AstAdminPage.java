package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.controllers.admin.AdminPage;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class AstAdminPage extends AdminPage {
    private final AstAdminSettings settings;
    private final String jspHome;

    public AstAdminPage(
            @NotNull PagePlaces pagePlaces,
            @NotNull WebControllerManager controllerManager,
            @NotNull PluginDescriptor descriptor,
            @NotNull AstAdminSettings settings) {
        super(pagePlaces);
        this.settings = settings;
        this.jspHome = descriptor.getPluginResourcesPath();

        setPluginName(Constants.PLUGIN_NAME);
        setIncludeUrl(descriptor.getPluginResourcesPath("adminPage.jsp"));
        setTabTitle(Labels.PLUGIN_TAB_TITLE);
        register();

        Loggers.SERVER.info("PT AI configuration page registered");
    }

    @NotNull
    @Override
    public String getGroup() {
        return INTEGRATIONS_GROUP;
    }

    @Override
    public void fillModel(@NotNull Map<String, Object> model, @NotNull HttpServletRequest request) {
        super.fillModel(model, request);

        BasePropertiesBean bean = new BasePropertiesBean(null);
        settings.getProperties().forEach((k, v) -> bean.setProperty(k.toString(), v.toString()));

        model.put("propertiesBean", bean);

        // This key is used to encrypt sensitive data while being sent from client to server
        model.put("hexEncodedPublicKey", RSACipher.getHexEncodedPublicKey());
    }

}
