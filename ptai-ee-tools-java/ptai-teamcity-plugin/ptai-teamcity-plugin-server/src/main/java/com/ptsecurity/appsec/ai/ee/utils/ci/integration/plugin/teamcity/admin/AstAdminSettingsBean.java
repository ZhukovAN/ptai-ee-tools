package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.controllers.RememberState;
import jetbrains.buildServer.controllers.StateField;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.util.StringUtil;
import lombok.Getter;
import lombok.Setter;

public class AstAdminSettingsBean extends BasePropertiesBean {
    public AstAdminSettingsBean(
            String url,
            String user, String token,
            String certificates) {
        super(null);

        this.setProperty(Params.URL, url);
        this.setProperty(Params.USER, user);
        this.setProperty(Params.TOKEN, token);
        this.setProperty(Params.CERTIFICATES, certificates);

        rememberState();
    }

    public String getHexEncodedPublicKey() {
        return RSACipher.getHexEncodedPublicKey();
    }
}


