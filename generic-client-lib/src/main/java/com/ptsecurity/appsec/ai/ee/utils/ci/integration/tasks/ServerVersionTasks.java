package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Map;

public interface ServerVersionTasks {
    @Getter
    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    enum Component {
        AIC("aic"),
        AIE("aie");

        private final String value;
    }

    Map<Component, String> current() throws GenericException;
}
