package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.AstPolicyViolationException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.Base;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

import static com.ptsecurity.appsec.ai.ee.scan.settings.Policy.State.REJECTED;

@Slf4j
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@ToString
public class FailIfAstFailed extends AbstractTool implements Base {
    @Override
    public void validate() throws GenericException {}

    @Override
    public void execute(
            @NonNull final ScanBrief scanBrief) throws GenericException {
        // OK, scan complete, let's check for policy violations
        Policy.State policyState = Optional.of(scanBrief)
                .map(ScanBrief::getPolicyState)
                .orElseThrow(() -> GenericException.raise(
                        "PT AI server API error",
                        new NullPointerException("Failed to get finished job policy assessment state")));

        if (!REJECTED.equals(policyState)) return;

        // AST policy assessment failed
        info(Resources.i18n_ast_result_status_failed_policy_label());
        throw GenericException.raise(
                "AST policy assessment failed",
                new AstPolicyViolationException());
    }
}
