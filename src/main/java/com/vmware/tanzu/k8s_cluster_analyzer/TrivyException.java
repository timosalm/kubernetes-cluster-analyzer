package com.vmware.tanzu.k8s_cluster_analyzer;

public class TrivyException extends Exception {
    public TrivyException(int returnCode) {
        super("Return code: %s".formatted(returnCode));
    }
}
