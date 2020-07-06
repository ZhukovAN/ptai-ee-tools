package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.client;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.config.ConsulConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service.SastService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Slf4j
@Component
public class PtaiClient extends Client {
    @Value("${server.ssl.trust-store-type}")
    private String trustStoreType;

    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    @Value("${server.ssl.trust-store}")
    private String trustStore;

    @Value("${server.ssl.key-store-type}")
    private String keyStoreType;

    @Value("${server.ssl.key-store-password}")
    private String keyStorePassword;

    @Value("${server.ssl.key-store}")
    private String keyStore;

    @Value("${ptai-backend-services.ptai-key-alias}")
    private String ptaiKeyAlias;

    @Value("${ptai-backend-services.ptai-key-password}")
    private String ptaiKeyPassword;

    @Value("${ptai-backend-services.ptai-url}")
    private String ptaiUrl;

    @Autowired
    private SastService sastService;

    @PostConstruct
    private void postConstruct() {
        // As PT AI EE gateway service is registered in Consul, the primary data source is
        // Consul ervices registry itself. If there's no data there than Spring will
        // read this parameter from properties:
        // 1. From services/integrationServer/data key in Consul
        // 2. From application.yml file
        setUrl(sastService.getPtaiGatewayUri().orElse(ptaiUrl));
        setTrustStoreFile(trustStore);
        setTrustStoreType(trustStoreType);
        setTrustStorePassword(trustStorePassword);

        setKeyStoreFile(keyStore);
        setKeyStoreType(keyStoreType);
        setKeyStorePassword(keyStorePassword);
        setKeyAlias(ptaiKeyAlias);
        setKeyPassword(ptaiKeyPassword);

        this.init(false);
    }

    @Autowired
    ResourceLoader resourceLoader;

    @Override
    protected void loadKeyStore(KeyStore keyStore, String path, char[] pass) throws IOException, CertificateException, NoSuchAlgorithmException {
        InputStream resource = resourceLoader.getResource(path).getInputStream();
        keyStore.load(resource, pass);
    }

    @Override
    public void log(String value) {
        log.info(this.logPrefix + value);
    }

    @Override
    public void log(String format, Object ... value) {
        log.info(String.format(format, value));
    }

    @Override
    public void log(Exception exception) {
        if (StringUtils.isNotEmpty(exception.getMessage()))
            this.log("%s", exception.getMessage());
        if (this.verbose)
            log.error(exception.getMessage(), exception);
    }
}
