package com.vmware.tanzu.k8s_cluster_analyzer;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@RefreshScope
@Configuration
@ConfigurationProperties("analyzer")
public class AnalyzerConfig {

    private List<Classifier> sbomClassifiers;
    private List<Classifier> containerNameClassifiers;
    private String excludedNamespaces;
    private String formattedAnalyzerIntro;

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

    public String getFormattedAnalyzerIntro() {
        return formattedAnalyzerIntro;
    }

    public void setFormattedAnalyzerIntro(String formattedAnalyzerIntro) {
        this.formattedAnalyzerIntro = formattedAnalyzerIntro;
    }
}
