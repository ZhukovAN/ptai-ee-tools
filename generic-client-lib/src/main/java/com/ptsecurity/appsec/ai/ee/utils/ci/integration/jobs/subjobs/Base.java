package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import lombok.*;
import lombok.experimental.SuperBuilder;

@NoArgsConstructor
@SuperBuilder
@AllArgsConstructor
public abstract class Base {
    @Getter @Setter
    protected GenericAstJob owner;

    public void attach(@NonNull final GenericAstJob owner) {
        this.owner = owner;
        this.owner.addSubJob(this);
    }

    public abstract void validate() throws GenericException;
    public abstract void execute(@NonNull final ScanBrief scanBrief) throws GenericException;
}
