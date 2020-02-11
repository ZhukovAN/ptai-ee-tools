package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository.RoleRepository;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository.UserRepository;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service.AdminService;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.security.Key;
import java.security.KeyStore;
import java.util.Date;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc(printOnlyOnFailure = false)
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class BaseIT {
    @Value("${local.server.port}")
    protected int port;

    @Autowired
    protected MockMvc mvc;

    @Value("${server.ssl.trust-store-password}")
    protected String trustStorePassword;

    @Value("${server.ssl.trust-store}")
    protected Resource trustStore;

    @Value("${server.ssl.key-store-type}")
    protected String keyStoreType;

    @Value("${server.ssl.key-store-password}")
    protected String keyStorePassword;

    @Value("${server.ssl.key-store}")
    protected Resource keyStore;

    @Value("${ptai-authorization-server.sign-key-alias}")
    protected String signKeyAlias;

    protected static String rootUrl = null;
    protected final static String apiRandomString = "/api/admin/random";
    protected final static String apiPasswordEncode = "/api/admin/encode?password={password}";
    protected final static String apiAccessToken = "/oauth/token";

    // For this client access token lifetime is 1 second only and refresh token - 2 seconds
    protected final static String clientIdFast = "unit-test-client-fast";
    protected final static String clientIdNormal = "unit-test-client";
    protected final static String clientSecret = "IMfiy4f3uvGjKD4v4yB6C5NmHTLwmC55";

    protected static final String loginTestAdmin = "testAdmin";
    protected static final String loginTestUser = "testUser";
    protected static final String password = "P@ssw0rd";

    protected Key jwtPublicKey = null;

    @Autowired
    protected UserRepository userRepository;
    @Autowired
    protected AdminService adminService;

    @BeforeAll
    public void initAll() throws Exception {
        rootUrl = "https://localhost:" + port;

        User admin = User.builder()
                .username(loginTestAdmin)
                .password(password)
                .build();
        if (null == userRepository.findByUsername(loginTestAdmin))
            adminService.addUser(admin, new String[] {"ADMIN", "USER"});

        User user = User.builder()
                .username(loginTestUser)
                .password(password)
                .build();
        if (null == userRepository.findByUsername(loginTestUser))
            adminService.addUser(user, new String[] {"USER"});
        KeyStore ks = KeyStore.getInstance(keyStoreType);
        char[] pass = StringUtils.isEmpty(this.keyStorePassword) ? "".toCharArray() : this.keyStorePassword.toCharArray();
        ks.load(keyStore.getInputStream(), pass);
        jwtPublicKey = ks.getCertificate(signKeyAlias).getPublicKey();
    }

    @AfterAll
    public void finiAll() {
        userRepository.delete(userRepository.findByUsername(loginTestAdmin));
        userRepository.delete(userRepository.findByUsername(loginTestUser));
    }

    protected void waitForExpiration(String message, String token) throws InterruptedException {
        System.out.println(message);
        Date exp = Jwts.parser().setSigningKey(jwtPublicKey).parseClaimsJws(token).getBody().getExpiration();
        do {
            Thread.sleep(200);
            System.out.print(".");
        } while (exp.after(new Date()));
        System.out.println();
    }
}
