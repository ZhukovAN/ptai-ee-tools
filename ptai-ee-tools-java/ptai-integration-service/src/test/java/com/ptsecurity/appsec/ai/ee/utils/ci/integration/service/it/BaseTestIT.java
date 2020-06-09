package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.UserData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service.AdminService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.UUID;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc(secure = false)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ActiveProfiles("integration-test")
public abstract class BaseTestIT {
    protected final static String CLIENT_ID = "unit-test-client";
    protected final static String CLIENT_SECRET = "IMfiy4f3uvGjKD4v4yB6C5NmHTLwmC55";
    protected static final String ADMIN = "junit-admin-" + UUID.randomUUID().toString();
    protected static final String ADMINTOKEN = UUID.randomUUID().toString();
    protected static final String USER = "junit-user-" + UUID.randomUUID().toString();
    protected static final String USERTOKEN = UUID.randomUUID().toString();

    protected static Path KEYSTORE = null;
    protected static Path TRUSTSTORE = null;

    @Autowired
    protected AdminService adminService;

    @BeforeAll
    public void init() throws URISyntaxException, IOException {
        KEYSTORE = Paths.get(BaseTestIT.class.getClassLoader().getResource("keys/keystore.jks").toURI());
        TRUSTSTORE = Paths.get(BaseTestIT.class.getClassLoader().getResource("keys/truststore.jks").toURI());
        // Create two test users - admin and user. There's no need to delete them as
        // integration tests use in-memory H2 database
        adminService.addUser(
                new UserData()
                        .name(ADMIN)
                        .password(ADMINTOKEN)
                        .roles(Arrays.asList("ADMIN", "USER")));
        adminService.addUser(
                new UserData()
                        .name(USER)
                        .password(USERTOKEN)
                        .roles(Arrays.asList("USER")));
    }

    @LocalServerPort
    protected int port;

    @Autowired
    protected MockMvc mvc;

    /**
     * Test clients; 0 - admin client, 1 - user client
     */
    protected Client[] client = new Client[2];

    @BeforeEach
    public void initClient() {
        for (int i = 0 ; i < 2 ; i++) {
            client[i] = new Client();
            client[i].setUrl("http://localhost:" + port);
            client[i].setClientId(CLIENT_ID);
            client[i].setClientSecret(CLIENT_SECRET);
            client[i].setUserName(0 == i ? ADMIN : USER);
            client[i].setPassword(0 == i ? ADMINTOKEN : USERTOKEN);
            client[i].init();
        }
    }

    @AfterEach
    public void finiClient() {
        client = null;
    }
}
