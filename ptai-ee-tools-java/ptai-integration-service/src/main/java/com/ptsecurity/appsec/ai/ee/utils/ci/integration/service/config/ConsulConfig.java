package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Getter
@Setter
@RefreshScope
@Configuration
@Validated
@EnableConfigurationProperties
public class ConsulConfig {
    @Value("${ptai-backend-services.ptai-key-alias}")
    private String ptaiKeyAlias;
    @Value("${ptai-backend-services.ci-job-name}")
    private String ciJobName;
    @Value("${ptai-backend-services.ci-url}")
    private String ciUrl;
    @Value("${server.ssl.key-alias}")
    private String keyAlias;
}
