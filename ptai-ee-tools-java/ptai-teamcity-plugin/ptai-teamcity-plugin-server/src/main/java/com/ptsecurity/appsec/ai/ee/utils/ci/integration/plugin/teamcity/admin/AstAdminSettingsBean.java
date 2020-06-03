package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import jetbrains.buildServer.controllers.RememberState;
import jetbrains.buildServer.controllers.StateField;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.util.StringUtil;
import lombok.Getter;
import lombok.Setter;

public class AstAdminSettingsBean extends RememberState {

    @Getter @Setter @StateField
    protected String ptaiGlobalUrl;
    @Getter @Setter @StateField
    protected String ptaiGlobalUser;
    @Getter @Setter @StateField
    protected String ptaiGlobalToken;
    @Getter @Setter @StateField
    protected String ptaiGlobalTrustedCertificates;

    public AstAdminSettingsBean(
            String ptaiGlobalUrl, String ptaiGlobalUser, String ptaiGlobalToken, String ptaiGlobalTrustedCertificates) {
        this.ptaiGlobalUrl = ptaiGlobalUrl;
        this.ptaiGlobalUser = ptaiGlobalUser;
        this.ptaiGlobalToken = ptaiGlobalToken;
        this.ptaiGlobalTrustedCertificates = ptaiGlobalTrustedCertificates;
        rememberState();
    }

    public String getHexEncodedPublicKey() {
        return RSACipher.getHexEncodedPublicKey();
    }

    public String getEncryptedPtaiGlobalToken() {
        return StringUtil.isEmpty(ptaiGlobalToken) ? "" : RSACipher.encryptDataForWeb(ptaiGlobalToken);
    }

    public void setEncryptedPtaiGlobalToken(String token) {
        this.ptaiGlobalToken = RSACipher.decryptWebRequestData(token);
    }

    protected String decryptValue(String encryptedValue) {
        String value = RSACipher.decryptWebRequestData(encryptedValue);
        if (EncryptUtil.isScrambled(value)) {
            try {
                value = EncryptUtil.unscramble(value);
            } catch (RuntimeException e) {
                value = "";
            }
        }
        return value;
    }
}


