package com.ptsecurity.appsec.ai.ee;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@RequiredArgsConstructor
@SuperBuilder
public class BaseScanSettings {
    @NonNull
    protected UUID id;

    public static enum ENGINE {
        AI, PM, TAINT, DC, FINGERPRINT, CONFIGURATION, BLACKBOX
    }
    protected final Set<ENGINE> engines = new HashSet<>();

    protected Boolean unpackUserPackages;

    protected Boolean downloadDependencies;

    protected Boolean usePublicAnalysisMethod;

    protected Boolean useEntryAnalysisPoint;

    public enum Language {
        PHP, JAVA, CSHARP, VBNET, JS, GO, CPP, PYTHON, SQL, OBJECTIVEC, SWIFT, KOTLIN
    }
    protected Language language;

    protected String url;

    protected Boolean useIncrementalScan;

    protected Boolean autocheckAfterScan;

    protected String customParameters;

    protected String javaParameters;
}
