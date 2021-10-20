package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Setter
@SuperBuilder
@RequiredArgsConstructor
@ToString
public class RawJson extends AbstractTool implements Export {
    @NonNull
    protected final GenericAstJob owner;

    @NonNull
    protected final Reports.RawData rawData;

    @Override
    public void validate() throws GenericException {
        ReportsTasks reportsTasks = new Factory().reportsTasks(owner.getClient());
        reportsTasks.check(rawData);
    }

    @Override
    public void execute(
            @NonNull final ScanBrief scanBrief) throws GenericException {
        ReportsTasks reportsTasks = new Factory().reportsTasks(owner.getClient());
        try {
            reportsTasks.generate(scanBrief.getProjectId(), scanBrief.getId(), rawData, owner.getFileOps());
        } catch (GenericException e) {
            warning(e);
        }
    }
}
