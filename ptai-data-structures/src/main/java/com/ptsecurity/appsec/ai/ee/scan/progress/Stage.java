package com.ptsecurity.appsec.ai.ee.scan.progress;

public enum Stage {
    UNKNOWN,
    ZIP,
    UPLOAD,
    VFSSETUP,
    INITIALIZE,
    PRECHECK,
    SCAN,
    FINALIZE,
    DONE,
    FAILED,
    ABORTED,
    ENQUEUED,
    AUTOCHECK;
}
