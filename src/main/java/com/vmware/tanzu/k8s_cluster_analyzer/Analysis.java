package com.vmware.tanzu.k8s_cluster_analyzer;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
public class Analysis implements Serializable {

    @Id
    private UUID id;
    private LocalDateTime createdAt;
    @OneToMany(cascade = {CascadeType.ALL})
    private List<Workload> workloads;
    private String kubernetesContext;

    public Analysis(String kubernetesContext, List<Workload> workloads) {
        this.id = UUID.randomUUID();
        this.createdAt = LocalDateTime.now();
        this.workloads = workloads;
        this.kubernetesContext = kubernetesContext;
    }

    public Analysis() {

    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public List<Workload> getWorkloads() {
        return workloads;
    }

    public void setWorkloads(List<Workload> workloads) {
        this.workloads = workloads;
    }

    public String getKubernetesContext() {
        return kubernetesContext;
    }

    public void setKubernetesContext(String kubernetesContext) {
        this.kubernetesContext = kubernetesContext;
    }

    public String getStatus() {
        var hasPendingClassifications = workloads.stream()
                .flatMap(workload -> workload.getContainers().stream())
                .anyMatch(container -> container.getStatus() == Classification.Status.PENDING);
        if (hasPendingClassifications) return "Pending";
        return "Completed";
    }
}
