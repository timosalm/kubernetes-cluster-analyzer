package com.vmware.tanzu.k8s_cluster_analyzer;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties("analyzer")
public class AnalyzerConfig {

    private List<Classifier> sbomClassifiers;
    private List<Classifier> containerNameClassifiers;
    private String excludedNamespaces;

    public String getExcludedNamespaces() {
        return excludedNamespaces;
    }

    public void setExcludedNamespaces(String excludedNamespaces) {
        this.excludedNamespaces = excludedNamespaces;
    }

    public List<Classifier> getSbomClassifiers() {
        return sbomClassifiers;
    }

    public void setSbomClassifiers(List<Classifier> sbomClassifiers) {
        this.sbomClassifiers = sbomClassifiers;
    }

    public List<Classifier> getContainerNameClassifiers() {
        return containerNameClassifiers;
    }

    public void setContainerNameClassifiers(List<Classifier> containerNameClassifiers) {
        this.containerNameClassifiers = containerNameClassifiers;
    }
}
