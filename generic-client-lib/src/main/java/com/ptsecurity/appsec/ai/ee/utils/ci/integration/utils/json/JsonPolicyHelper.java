package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

public class JsonPolicyHelper extends BaseJsonHelper {
    public static Policy[] verify(final String json) throws GenericException {
        if (StringUtils.isEmpty(json)) return null;
        return call(() -> {
            ObjectMapper mapper = createObjectMapper();
            return mapper.readValue(json, Policy[].class);
        }, "JSON policy parse failed");
    }

    public static String serialize(@NonNull final Policy[] policy) throws GenericException {
        return CallHelper.call(
                () -> BaseJsonHelper.serialize(policy),
                "JSON policy serialization failed");
    }

    /**
     * @param policyJson JSON-defined AST policy
     * @return Minimized JSON-defined AST policy, i.e. without comments, formatting etc.
     * @throws GenericException
     */
    public static String minimize(@NonNull String policyJson) throws GenericException {
        Policy[] policy = verify(policyJson);
        return serialize(policy);
    }
}
