package com.vmware.tanzu.k8s_cluster_analyzer;

import io.kubernetes.client.openapi.models.V1Container;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
public class Container {

    @Id
    private UUID id;
    private String name;
    private String image;
    @OneToMany(cascade = CascadeType.ALL)
    private List<Classification> classifications = new ArrayList<>();
    @Lob
    private String sBom;

    public Container(String name, String image) {
        this.id = UUID.randomUUID();
        this.name = name;
        this.image = image;
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
        }
    }

    public String getSBom() {
        return sBom;
    }

    public void setSBom(String sBom) {
        this.sBom = sBom;
    }
}
