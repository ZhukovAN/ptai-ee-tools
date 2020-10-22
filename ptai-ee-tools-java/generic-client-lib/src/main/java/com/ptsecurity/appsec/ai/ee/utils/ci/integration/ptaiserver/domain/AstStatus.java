package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.PolicyState;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanError;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanResult;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Stage;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import javax.annotation.Nullable;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public enum AstStatus {
    /**
     * Scan is not finished yet
     */
    UNKNOWN(Messages.ast_status_unknown()),
    /**
     * Scan complete, AST policy assessment failed
     */
    FAILURE(Messages.ast_status_failure()),
    /**
     * Scan complete, AST policy assessment success, but there were scan warnings or errors
     */
    UNSTABLE(Messages.ast_status_unstable()),

    /**
     * Scan complete, AST policy assessment success
     */
    SUCCESS(Messages.ast_status_success()),
    /**
     * Scan complete, AST policy not defined
     */
    POLICY_EMPTY(Messages.ast_status_policy_empty()),
    /**
     * Scan was terminated
     */
    ABORTED(Messages.ast_status_aborted()),
    /**
     * Scan error
     */
    ERROR(Messages.ast_status_error());

    @Getter
    private final String description;

    /**
     * Convert miscellaneous scan result attributes to AstStatus. We do use
     * pessimistic approach here: result is success only if scan is done,
     * policy assessment is OK and there were no scan errors
     * @param scanResult Scan result. For finished scans stage field valid
     *                   values are DONE, ABORTED and FAILED
     * @param scanErrors List of scan errors and warnings
     * @return
     */
    public static AstStatus convert(
            @NonNull ScanResult scanResult, @Nullable List<ScanError> scanErrors) {
        Stage stage = Optional.of(scanResult)
                .map(r -> r.getProgress())
                .map(p -> p.getStage()).orElse(null);
        if (null == stage) return ERROR;

        if (!Stage.DONE.equals(stage)) {
            if (Stage.ABORTED.equals(stage))
                return ABORTED;
            else if (Stage.FAILED.equals(stage))
                return ERROR;
        }
        // OK, scan complete, let's check for policy violations
        PolicyState policyState = Optional.of(scanResult)
                .map(r -> r.getStatistic())
                .map(s -> s.getPolicyState())
                .orElse(null);
        if (null == policyState) return ERROR;

        // TODO: Swap REJECTED/CONFIRMED states when https://jira.ptsecurity.com/browse/AI-4866 will be fixed
        if (PolicyState.CONFIRMED.equals(policyState))
            return FAILURE;
        // OK, policy assessment success or policy not defined, let's check for scan errors/warnings
        if (null != scanErrors && scanErrors.stream().findAny().isPresent())
            return UNSTABLE;

        return PolicyState.NONE.equals(policyState) ? POLICY_EMPTY : SUCCESS;
    }
}
