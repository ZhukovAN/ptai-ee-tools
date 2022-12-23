package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

@Getter
@Setter
@Builder
public class PasswordCredentials extends BaseCredentials {
    /**
     * User name
     */
    @NonNull
    protected String user;

    /**
     * User password
     */
    protected String password;

    @Override
    public void validate() {
        if (StringUtils.isEmpty(user))
            throw GenericException.raise(Resources.i18n_ast_settings_server_user_message_empty(), new IllegalArgumentException(user));
    }
}
