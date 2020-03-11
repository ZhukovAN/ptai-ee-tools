package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

public class Main {
    public static void main(String[] args) {
        switch (new SlimSastJob().execute(args)) {
            case UNSTABLE: System.exit(2);
            case FAILURE: System.exit(1);
            case SUCCESS: System.exit(0);
            default: System.exit(2);
        }
    }
}
