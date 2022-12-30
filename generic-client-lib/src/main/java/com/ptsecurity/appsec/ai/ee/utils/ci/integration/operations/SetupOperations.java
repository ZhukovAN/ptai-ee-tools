package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.misc.tools.exceptions.GenericException;

import java.util.UUID;

public interface SetupOperations {
    UUID setupProject() throws GenericException;
}
