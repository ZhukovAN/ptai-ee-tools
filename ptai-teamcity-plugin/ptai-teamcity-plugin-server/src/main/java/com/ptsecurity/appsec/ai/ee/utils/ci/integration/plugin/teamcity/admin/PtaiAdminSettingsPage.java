package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.PtaiAdminSettings;
import jetbrains.buildServer.controllers.admin.AdminPage;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class PtaiAdminSettingsPage extends AdminPage {
    private final PtaiAdminSettings ptaiAdminSettings;
    private final String jspHome;

    protected PtaiAdminSettingsPage(
            @NotNull PagePlaces pagePlaces,
            @NotNull WebControllerManager controllerManager,
            @NotNull PluginDescriptor descriptor,
            @NotNull PtaiAdminSettings ptaiAdminSettings) {
        super(pagePlaces);
        this.ptaiAdminSettings = ptaiAdminSettings;
        setPluginName("ptsecurity");
        setIncludeUrl(descriptor.getPluginResourcesPath("ptaiAdminSettings.jsp"));
        this.jspHome = descriptor.getPluginResourcesPath();
        setTabTitle("Positive Technologies");
        register();
        Loggers.SERVER.info("PTAI configuration page registered");
    }

    @Override
    public void fillModel(@NotNull Map<String, Object> model, @NotNull HttpServletRequest request){
        super.fillModel(model, request);
        model.put("ptaiAdminSettings", new PtaiAdminSettingsBean(
                ptaiAdminSettings.getCaCertsPem(),
                ptaiAdminSettings.getPtaiServerUrl(),
                ptaiAdminSettings.getPtaiKeyPem(),
                ptaiAdminSettings.getPtaiKeyPemPassword(),
                ptaiAdminSettings.getJenkinsServerUrl(),
                ptaiAdminSettings.getJenkinsJobName(),
                ptaiAdminSettings.getJenkinsLogin(),
                ptaiAdminSettings.getJenkinsPassword()));

        model.put("jspHome", this.jspHome);
    }

    @NotNull
    @Override
    public String getGroup() {
        return INTEGRATIONS_GROUP;
    }
}
