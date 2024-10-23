package com.vmware.tanzu.k8s_cluster_analyzer;

import io.kubernetes.client.openapi.models.V1Container;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToMany;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
public class Container implements Serializable {

    @Id
    private UUID id;
    private String name;
    private String image;
    @OneToMany(cascade = CascadeType.ALL)
    private List<Classification> classifications = new ArrayList<>();
    @Lob
    private String sBom;
    private Integer totalCveCount;
    private Integer criticalCveCount;
    private Integer highCveCount;
    private Classification.Status status;
    private String errorMessage;

    public Container(String name, String image) {
        this.id = UUID.randomUUID();
        this.name = name;
        this.image = image;
        this.status = Classification.Status.PENDING;
    }

    public Container() {

    }

    public static Container from(V1Container container) {
        return new Container(container.getName(), container.getImage());
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public List<Classification> getClassifications() {
        return classifications;
    }

    public void setClassifications(List<Classification> classifications) {
        this.classifications = classifications;
    }

    public void addClassification(Classification classification) {
        if (classification != null) {
            this.classifications.add(classification);
            status = Classification.Status.COMPLETED;
        }
    }

    public String getSBom() {
        return sBom;
    }

    public void setSBom(String sBom) {
        this.sBom = sBom;
    }

    public Integer getTotalCveCount() {
        return totalCveCount;
    }

    public void setTotalCveCount(Integer totalCveCount) {
        this.totalCveCount = totalCveCount;
    }

    public Integer getCriticalCveCount() {
        return criticalCveCount;
    }

    public void setCriticalCveCount(Integer criticalCveCount) {
        this.criticalCveCount = criticalCveCount;
    }

    public Integer getHighCveCount() {
        return highCveCount;
    }

    public void setHighCveCount(Integer highCveCount) {
        this.highCveCount = highCveCount;
    }

    public Classification.Status getStatus() {
        return status;
    }

    public void setStatus(Classification.Status status) {
        this.status = status;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void addAll(List<Classification> classifications) {
        classifications.forEach(this::addClassification);
    }

    public String getsBom() {
        return sBom;
    }

    public void setsBom(String sBom) {
        this.sBom = sBom;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
