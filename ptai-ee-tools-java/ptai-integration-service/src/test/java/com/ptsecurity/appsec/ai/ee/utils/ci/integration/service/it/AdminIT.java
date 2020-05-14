package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.UserData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service.AdminService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.List;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc(secure = false)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ActiveProfiles("integration-test")
@DisplayName("Test PT AI EE integration service admin functions")
public class AdminIT {
    protected final static String CLIENT_ID = "unit-test-client";
    protected final static String CLIENT_SECRET = "IMfiy4f3uvGjKD4v4yB6C5NmHTLwmC55";
    protected static final String ADMIN = "testAdmin";
    protected static final String USER = "testUser";
    protected static final String PASSWORD = "P@ssw0rd";

    protected static Path KEYSTORE = null;
    protected static Path TRUSTSTORE = null;

    @Autowired
    protected AdminService adminService;

    @BeforeAll
    public void init() throws URISyntaxException, IOException {
        KEYSTORE = Paths.get(AdminIT.class.getClassLoader().getResource("keys/keystore.jks").toURI());
        TRUSTSTORE = Paths.get(AdminIT.class.getClassLoader().getResource("keys/truststore.jks").toURI());
        UserData admin = new UserData();
        admin.setName(ADMIN);
        admin.setPassword(PASSWORD);
        admin.setRoles(Arrays.asList("ADMIN", "USER"));
        adminService.addUser(admin);
    }

    // @Value("${local.server.port}")
    @LocalServerPort
    protected int port;

    @Autowired
    protected MockMvc mvc;

    protected Client client;

    @BeforeEach
    public void initClient() {
        client = new Client();
        client.setUrl("http://localhost:" + port);
        client.setClientId(CLIENT_ID);
        client.setClientSecret(CLIENT_SECRET);
        client.setUserName(ADMIN);
        client.setPassword(PASSWORD);
        client.init();
    }

    @AfterEach
    public void finiClient() {
        client = null;
    }

    @Test
    @DisplayName("List PT AI EE integration service users")
    public void listUsers() throws Exception {
        List<User> users = client.getAdminApi().getUsers();
        for (User user : users)
            System.out.println(user.getName());
    }
}
