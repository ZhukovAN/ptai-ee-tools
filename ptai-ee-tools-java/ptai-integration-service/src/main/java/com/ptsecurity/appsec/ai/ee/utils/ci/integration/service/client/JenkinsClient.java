package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.client;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.config.ConsulConfig;
import lombok.Getter;
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
public class JenkinsClient extends Client {
    @Value("${server.ssl.trust-store-type}")
    private String trustStoreType;

    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    @Value("${server.ssl.trust-store}")
    private String trustStore;

    @Getter
    @Value("${ptai-backend-services.ci-url}")
    private String ciUrl;
    @Getter
    @Value("${ptai-backend-services.ci-user-name}")
    private String ciUserName;
    @Getter
    @Value("${ptai-backend-services.ci-api-token}")
    private String ciApiToken;
    @Getter
    @Value("${ptai-backend-services.ci-job-name}")
    private String ciJobName;

    @Getter
    @Value("${ptai-backend-services.ci-max-retry}")
    private Integer maxRetry;

    @Getter
    @Value("${ptai-backend-services.ci-retry-delay}")
    private Integer retryDelay;

    @Autowired
    ConsulConfig consulConfig;

    @PostConstruct
    private void postConstruct() {
        this.setUrl(ciUrl);
        this.setTrustStoreFile(trustStore);
        this.setTrustStoreType(trustStoreType);
        this.setTrustStorePassword(trustStorePassword);
        this.setUserName(ciUserName);
        this.setToken(ciApiToken);
        this.setVerbose(verbose);
        // jenkinsSastJob.setConsoleLog(System.out);
        // client.setJobName(sastJob);
        // jenkinsSastJob.setProjectName(ptaiPrj.getName());
        // jenkinsSastJob.setNodeName(node);

        this.init();
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
            this.log("%s\r\n", exception.getMessage());
        if (this.verbose)
            log.error(exception.getMessage(), exception);
    }
}
