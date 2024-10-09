package com.vmware.tanzu.k8s_cluster_analyzer;

public record Classifier(String name, String type, String subType, String technology, String regex, int fit,
                          String documentation) {
}
