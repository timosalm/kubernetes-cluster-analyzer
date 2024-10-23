package com.vmware.tanzu.k8s_cluster_analyzer;

public class TrivyException extends Exception {
    public TrivyException(int returnCode, String consoleOutput) {
        super("Return code: %s Console output: %s".formatted(returnCode, consoleOutput));
    }
}
