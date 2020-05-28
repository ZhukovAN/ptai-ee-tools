package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain;

import com.ptsecurity.appsec.ai.ee.aic.ExitCode;
import lombok.NonNull;

public enum PtaiResultStatus {
    UNKNOWN, FAILURE, UNSTABLE, SUCCESS, ABORTED, ERROR;

    public static PtaiResultStatus convert(@NonNull Integer exitCode) {
        PtaiResultStatus res = ERROR;
        if (ExitCode.CODE_SUCCESS.getCode().equals(exitCode))
            res = SUCCESS;
        else if (ExitCode.CODE_WARNING.getCode().equals(exitCode))
            res = UNSTABLE;
        else if (ExitCode.CODE_FAILED.getCode().equals(exitCode))
            res = FAILURE;
        else if (ExitCode.CODE_ERROR_TERMINATED.getCode().equals(exitCode))
            res = ABORTED;
        return res;
    }
}
