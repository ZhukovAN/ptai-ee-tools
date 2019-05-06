package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.util.StringUtil;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.util.Properties;


public class PtaiAdminSettings {
    @Getter @Setter
    protected String caCertsPem;

    @Getter @Setter
    protected String ptaiServerUrl;
    @Getter @Setter
    protected String ptaiKeyPem;
    @Getter @Setter
    protected String ptaiKeyPemPassword;

    @Getter @Setter
    protected String jenkinsServerUrl;
    @Getter @Setter
    protected String jenkinsJobName;
    @Getter @Setter
    protected String jenkinsLogin;
    @Getter @Setter
    protected String jenkinsPassword;

    private final ServerPaths serverPaths;

    public void init() {
        loadConfiguration();
    }

    public PtaiAdminSettings(@NotNull ServerPaths serverPaths) throws IOException {
        this.serverPaths = serverPaths;
        loadConfiguration();
    }

    private File getConfigFile() {
        File res = new File(this.serverPaths.getConfigDir(), "ptai-plugin.properties");
        if (res.exists()) return res;
        try {
            res.createNewFile();
            return res;
        } catch (IOException e) {
            return null;
        }
    }

    private void loadConfiguration() {
        File file = getConfigFile();
        if (file == null)
            throw new RuntimeException("Property file not found");
        try (FileReader reader = new FileReader(file)) {
            Properties prop = new Properties();
            prop.load(reader);

            this.caCertsPem = prop.getProperty("caCertsPem", "");
            this.ptaiServerUrl = prop.getProperty("ptaiServerUrl", "");
            this.ptaiKeyPem = prop.getProperty("ptaiKeyPem", "");
            this.ptaiKeyPemPassword = unscramble(prop.getProperty("ptaiKeyPemPassword", ""));
            this.jenkinsServerUrl = prop.getProperty("jenkinsServerUrl", "");
            this.jenkinsJobName = prop.getProperty("jenkinsJobName", "");
            this.jenkinsLogin = prop.getProperty("jenkinsLogin", "");
            this.jenkinsPassword = unscramble(prop.getProperty("jenkinsPassword", ""));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void saveConfiguration() throws IOException {
        File file = getConfigFile();
        if (file == null)
            throw new RuntimeException("Property file not found");

        Properties prop = new Properties();
        FileWriter outFile = new FileWriter(file);
        prop.put("caCertsPem", this.caCertsPem);
        prop.put("ptaiServerUrl", this.ptaiServerUrl);
        prop.put("ptaiKeyPem", this.ptaiKeyPem);
        prop.put("ptaiKeyPemPassword", scramble(this.ptaiKeyPemPassword));
        prop.put("jenkinsServerUrl", this.jenkinsServerUrl);
        prop.put("jenkinsJobName", this.jenkinsJobName);
        prop.put("jenkinsLogin", this.jenkinsLogin);
        prop.put("jenkinsPassword", scramble(this.jenkinsPassword));

        prop.store(outFile, null);
        outFile.close();
    }

    private String scramble(String str) {
        return StringUtil.isEmpty(str) ? str : EncryptUtil.scramble(str);
    }

    private String unscramble(String str) {
        return StringUtil.isEmpty(str) ? str : EncryptUtil.unscramble(str);
    }
}
