package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.PtaiAdminConfig;
import jetbrains.buildServer.controllers.admin.AdminPage;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class PtaiAdminPage extends AdminPage {
    private final PtaiAdminConfig ptaiAdminConfig;

    protected PtaiAdminPage(@NotNull PagePlaces pagePlaces, @NotNull WebControllerManager controllerManager, @NotNull PluginDescriptor descriptor, @NotNull PtaiAdminConfig ptaiAdminConfig) {
        super(pagePlaces);
        this.ptaiAdminConfig = ptaiAdminConfig;
        setPluginName("ptsecurity");
        setIncludeUrl(descriptor.getPluginResourcesPath("adminPage.jsp"));
        setTabTitle("Positive Technologies");
        register();
    }

    @Override
    public void fillModel(@NotNull Map<String, Object> model, @NotNull HttpServletRequest request){
        super.fillModel(model, request);
        model.put("caCertsPem", ptaiAdminConfig.getCaCertsPem());
        model.put("ptaiServerUrl", ptaiAdminConfig.getPtaiServerUrl());
        model.put("ptaiKeyPem", ptaiAdminConfig.getPtaiKeyPem());
        model.put("ptaiKeyPemPassword", ptaiAdminConfig.getPtaiKeyPemPassword());
        model.put("jenkinsServerUrl", ptaiAdminConfig.getJenkinsServerUrl());
        model.put("jenkinsJobName", ptaiAdminConfig.getJenkinsJobName());
        model.put("jenkinsLogin", ptaiAdminConfig.getJenkinsLogin());
        model.put("jenkinsPassword", ptaiAdminConfig.getJenkinsPassword());
    }

    @NotNull
    @Override
    public String getGroup() {
        return INTEGRATIONS_GROUP;
    }
}
