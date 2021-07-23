package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;

public interface CheckServerTasks {
    ServerCheckResult check() throws GenericException;
}
