package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.java.Log;

@Log
public abstract class BaseAst {
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class ExitCode {
        @Getter
        protected int code;

        public static final ExitCode SUCCESS = new ExitCode(0);
        public static final ExitCode FAILED = new ExitCode(1);
        public static final ExitCode WARNINGS = new ExitCode(2);
        public static final ExitCode ERROR = new ExitCode(3);
        public static final ExitCode INVALID_INPUT = new ExitCode(1000);
    }
}
