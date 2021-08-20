package com.ptsecurity.appsec.ai.ee.scan.progress;

public enum Stage {
    SETUP,
    ZIP,
    UPLOAD,
    ENQUEUED,
    INITIALIZE,
    VFSSETUP,
    PRECHECK,
    SCAN,
    FINALIZE,
    AUTOCHECK,
    DONE,
    FAILED,
    ABORTED,
    UNKNOWN
}
