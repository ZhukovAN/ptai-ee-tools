package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import jetbrains.buildServer.controllers.RememberState;
import jetbrains.buildServer.controllers.StateField;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.util.StringUtil;
import lombok.Getter;
import lombok.Setter;

public class PtaiAdminSettingsBean extends RememberState {

    @Getter @Setter @StateField
    protected String caCertsPem;
    @Getter @Setter @StateField
    protected String ptaiServerUrl;
    @Getter @Setter @StateField
    protected String ptaiKeyPem;
    @Getter @Setter @StateField
    protected String ptaiKeyPemPassword;

    @Getter @Setter @StateField
    protected String jenkinsServerUrl;
    @Getter @Setter @StateField
    protected String jenkinsJobName;
    @Getter @Setter @StateField
    protected String jenkinsLogin;
    @Getter @Setter @StateField
    protected String jenkinsPassword;

    public PtaiAdminSettingsBean(
            String caCertsPem,
            String ptaiServerUrl, String ptaiKeyPem, String ptaiKeyPemPassword,
            String jenkinsServerUrl, String jenkinsJobName, String jenkinsLogin, String jenkinsPassword) {
        this.caCertsPem = caCertsPem;
        this.ptaiServerUrl = ptaiServerUrl;
        this.ptaiKeyPem = ptaiKeyPem;
        this.ptaiKeyPemPassword = ptaiKeyPemPassword;
        this.jenkinsServerUrl = jenkinsServerUrl;
        this.jenkinsJobName = jenkinsJobName;
        this.jenkinsLogin = jenkinsLogin;
        this.jenkinsPassword = jenkinsPassword;
        rememberState();
    }

    public String getHexEncodedPublicKey() {
        return RSACipher.getHexEncodedPublicKey();
    }

    public String getEncryptedJenkinsPassword() {
        return StringUtil.isEmpty(jenkinsPassword) ? "" : RSACipher.encryptDataForWeb(jenkinsPassword);
    }

    public void setEncryptedJenkinsPassword(String password) {
        this.jenkinsPassword = RSACipher.decryptWebRequestData(password);
    }

    public String getEncryptedPtaiKeyPemPassword() {
        return StringUtil.isEmpty(ptaiKeyPem) ? "" : RSACipher.encryptDataForWeb(ptaiKeyPem);
    }

    public void setEncryptedPtaiKeyPemPassword(String password) {
        this.ptaiKeyPemPassword = RSACipher.decryptWebRequestData(password);
    }

    protected String decryptValue(String encryptedValue) {
        String password = RSACipher.decryptWebRequestData(encryptedValue);
        if (EncryptUtil.isScrambled(password)) {
            try {
                password = EncryptUtil.unscramble(password);
            } catch (RuntimeException e) {
                password = "";
            }
        }
        return password;
    }
}


