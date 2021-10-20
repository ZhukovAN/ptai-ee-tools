package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;

public interface Base {
    void validate() throws GenericException;
    void execute(@NonNull final ScanBrief scanBrief) throws GenericException;
}
