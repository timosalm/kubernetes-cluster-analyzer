package com.vmware.tanzu.k8s_cluster_analyzer;

import org.springframework.context.ApplicationEvent;

import java.util.List;

public class ContainerSBomAnalysisEvent extends ApplicationEvent {

    private final Workload workload;
    private final Container container;
    private final List<RegistryCredentials> registryCredentials;

    public ContainerSBomAnalysisEvent(Analysis analysis, Workload workload, Container container, List<RegistryCredentials> registryCredentials) {
        super(analysis);
        this.workload = workload;
        this.container = container;
        this.registryCredentials = registryCredentials;
    }

    public Analysis getSource() {
        return (Analysis) super.getSource();
    }

    public Workload getWorkload() {
        return this.workload;
    }

    public Container getContainer() {
        return container;
    }

    public List<RegistryCredentials> getRegistryCredentials() {
        return registryCredentials;
    }
}
