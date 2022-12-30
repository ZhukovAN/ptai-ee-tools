package com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

public interface TextOutput {
    void info(final String value);

    void info(@NonNull final String format, final Object ... values);

    void warning(final String value);

    void warning(@NonNull final GenericException e);

    void severe(@NonNull final String value);

    void severe(@NonNull final GenericException e);

    void fine(@NonNull final String value);

    void fine(@NonNull final String format, final Object ... values);
}
