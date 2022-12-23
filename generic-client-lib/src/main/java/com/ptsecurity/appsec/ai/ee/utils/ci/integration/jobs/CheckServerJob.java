package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTasks;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

import java.util.Objects;

@SuperBuilder
public class CheckServerJob extends AbstractJob {

    @Getter
    protected ServerCheckResult serverCheckResult;

    @Override
    protected void init() throws GenericException {

    }

    @Override
    protected void unsafeExecute() throws GenericException {
        CheckServerTasks task = new Factory().checkServerTasks(client);
        serverCheckResult = Objects.requireNonNull(task.check());
    }
}
