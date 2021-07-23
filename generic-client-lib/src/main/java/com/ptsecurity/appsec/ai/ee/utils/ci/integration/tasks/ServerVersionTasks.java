package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;

public interface ServerVersionTasks {
    String current() throws GenericException;
    String latest() throws GenericException;
}
