package com.vmware.tanzu.k8s_cluster_analyzer;

import org.springframework.context.ApplicationEvent;

import java.util.List;

public class ContainerSBomAnalysisEvent extends ApplicationEvent {

    private final Container container;
    private final List<RegistryCredentials> registryCredentials;

    public ContainerSBomAnalysisEvent(Workload source, Container container, List<RegistryCredentials> registryCredentials) {
        super(source);
        this.container = container;
        this.registryCredentials = registryCredentials;
    }

    public Workload getSource() {
        return (Workload) super.getSource();
    }

    public Container getContainer() {
        return container;
    }

    public List<RegistryCredentials> getRegistryCredentials() {
        return registryCredentials;
    }
}
