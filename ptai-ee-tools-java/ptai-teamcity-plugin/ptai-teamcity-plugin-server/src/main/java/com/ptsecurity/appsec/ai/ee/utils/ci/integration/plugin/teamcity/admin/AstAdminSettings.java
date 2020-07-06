package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.util.PropertiesUtil;
import jetbrains.buildServer.util.StringUtil;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

public class AstAdminSettings {
    @Getter
    private final Properties properties = new Properties();
    private final ServerPaths serverPaths;

    public void init() throws IOException {
        loadConfig();
    }

    public AstAdminSettings(@NotNull ServerPaths serverPaths) throws IOException {
        this.serverPaths = serverPaths;
        Path config = getConfigFile();
        if (!Files.exists(config))
            initConfig(config);
        loadConfig(config);
    }

    private Path getConfigFile() {
        return Paths.get(serverPaths.getConfigDir()).resolve("ptai-plugin.properties");
    }

    private void initConfig(@NotNull final Path path) throws IOException {
        this.properties.put(URL, Base.DEFAULT_PTAI_URL);
        this.properties.put(USER, "");
        this.properties.put(TOKEN, "");
        this.properties.put(CERTIFICATES, "");
        getConfigFile().toFile().getParentFile().mkdirs();
        PropertiesUtil.storeProperties(properties, path.toFile(), "PT AI EE");
    }

    private void loadConfig() throws IOException {
        Path path = getConfigFile();
        loadConfig(path);
    }

    private void loadConfig(@NotNull final Path path) throws IOException {
        try (FileReader reader = new FileReader(path.toFile())) {
            this.properties.load(reader);
            String pass = this.properties.getProperty(TOKEN, "");
            this.properties.setProperty(TOKEN, unscramble(pass));
        }
    }

    public void saveConfig() throws IOException {
        String pass = this.properties.getProperty(TOKEN, "");
        this.properties.setProperty(TOKEN, scramble(pass));
        PropertiesUtil.storeProperties(properties, getConfigFile().toFile(), "PT AI");
        this.properties.setProperty(TOKEN, pass);
    }

    public String getValue(String key) {
        return properties.getOrDefault(key, "").toString();
    }

    public void setValue(String key, String value) {
        properties.put(key, StringUtil.emptyIfNull(value));
    }

    private String scramble(String value) {
        return StringUtil.isEmpty(value) ? value : EncryptUtil.scramble(value);
    }

    private String unscramble(String value) {
        return StringUtil.isEmpty(value) ? value : EncryptUtil.unscramble(value);
    }
}
