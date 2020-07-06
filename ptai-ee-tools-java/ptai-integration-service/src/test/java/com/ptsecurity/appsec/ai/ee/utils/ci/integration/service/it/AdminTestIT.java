package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.UserData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service.AdminService;
import org.junit.jupiter.api.*;
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
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

@DisplayName("Test PT AI EE integration service admin functions")
public class AdminTestIT extends BaseTestIT {
    @Test
    @DisplayName("List PT AI EE integration service users")
    public void listUsers() throws Exception {
        List<User> users = client[0].getAdminApi().getUsers();
        for (User user : users)
            System.out.println(user.getName());
    }
}
