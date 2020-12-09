package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.serverSide.crypt.RSACipher;

public class AstAdminSettingsBean extends BasePropertiesBean {
    public AstAdminSettingsBean(
            String url,
            String token,
            String certificates, String insecure) {
        super(null);

        this.setProperty(Params.URL, url);
        this.setProperty(Params.TOKEN, token);
        this.setProperty(Params.CERTIFICATES, certificates);
        this.setProperty(Params.INSECURE, insecure);

        rememberState();
    }

    public String getHexEncodedPublicKey() {
        return RSACipher.getHexEncodedPublicKey();
    }
}


