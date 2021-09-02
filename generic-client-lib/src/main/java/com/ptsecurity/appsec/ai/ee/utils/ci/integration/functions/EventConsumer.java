package com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions;

import lombok.NonNull;

public interface EventConsumer {
    void process(@NonNull final Object event);
}
