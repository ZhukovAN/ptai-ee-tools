package com.ptsecurity.appsec.ai.ee.test.scan.settings;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.helpers.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.misc.tools.BaseTest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

@Slf4j
@DisplayName("Read and parse data from policy JSON resource file")
public class PolicyTest extends BaseTest {
    @Test
    @SneakyThrows
    @DisplayName("Load generic AST policy")
    public void loadGenericPolicy() {
        InputStream inputStream = getResourceStream("json/scan/settings/policy.generic.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        Policy[] policy = mapper.readValue(inputStream, Policy[].class);
        String policyRuleString = JsonPolicyHelper.serialize(policy[0].getScopes()[0].getRules()[0]);

        Assertions.assertNotNull(policy);
        Assertions.assertEquals(1, policy.length);
        Assertions.assertEquals(1, policy[0].getScopes().length);
        Assertions.assertEquals(3, policy[0].getScopes()[0].getRules().length);

        Optional<Policy.Scopes.Rules> rules = Arrays.stream(policy[0].getScopes()[0].getRules()).filter(Policy.Scopes.Rules::isRegex).findFirst();
        Assertions.assertTrue(rules.isPresent());
        Assertions.assertDoesNotThrow(() -> Pattern.compile(rules.get().getValue()));
    }
}
