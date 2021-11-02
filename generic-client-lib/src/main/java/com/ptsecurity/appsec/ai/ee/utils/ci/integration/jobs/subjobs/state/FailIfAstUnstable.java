package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.MinorAstErrorsException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
@Getter
@Setter
@SuperBuilder
@RequiredArgsConstructor
@ToString
public class FailIfAstUnstable extends Base {
    @Override
    public void validate() throws GenericException {}

    @Override
    public void execute(
            @NonNull final ScanBrief scanBrief) throws GenericException {
        // Let's process DONE stage warnings / errors
        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(owner.getClient());
        List<Error> errors = genericAstTasks.getScanErrors(scanBrief.getProjectId(), scanBrief.getId());

        // Check errors / warnings
        if (null == errors || errors.isEmpty()) return;
        owner.info(Resources.i18n_ast_result_status_failed_unstable_label());
        throw GenericException.raise(
                "AST failed due to minor errors / warnings during scan",
                new MinorAstErrorsException());
    }
}
