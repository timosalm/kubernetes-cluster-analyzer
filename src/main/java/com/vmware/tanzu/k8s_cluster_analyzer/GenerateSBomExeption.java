package com.vmware.tanzu.k8s_cluster_analyzer;

public class GenerateSBomExeption extends Exception {
    public GenerateSBomExeption(String containerImage) {
        super("SBOM generation failed for container " + containerImage);
    }
}
