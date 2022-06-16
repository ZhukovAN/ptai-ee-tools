package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CertificateHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.Validator;
import lombok.*;
import org.apache.commons.lang3.StringUtils;

@Setter
@Getter
@Builder
@RequiredArgsConstructor
public class TokenCredentials extends BaseCredentials {
    /**
     * PT AI server API token
     */
    @NonNull
    protected String token;

    @Override
    public void validate() {
        if (StringUtils.isEmpty(token))
            throw GenericException.raise(Resources.i18n_ast_settings_server_token_message_empty(), new IllegalArgumentException(token));
    }
}
