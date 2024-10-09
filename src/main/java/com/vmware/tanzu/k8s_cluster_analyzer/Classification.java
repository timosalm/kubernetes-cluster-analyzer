package com.vmware.tanzu.k8s_cluster_analyzer;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

import java.util.UUID;

@Entity
public class Classification {

    @Id
    private UUID id;
    private String type;
    private String subType;
    private String technology;
    private int fit;
    private String documentation;

    public Classification(String type, String subType, String technology, int fit, String documentation) {
        this.id = UUID.randomUUID();
        this.type = type;
        this.subType = subType;
        this.technology = technology;
        this.fit = fit;
        this.documentation = documentation;
    }

    public Classification() {
    }

    public static Classification from(Classifier classifier) {
        return new Classification(classifier.type(), classifier.subType(), classifier.technology(), classifier.fit(),
                classifier.documentation());
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSubType() {
        return subType;
    }

    public void setSubType(String subType) {
        this.subType = subType;
    }

    public String getTechnology() {
        return technology;
    }

    public void setTechnology(String technology) {
        this.technology = technology;
    }

    public int getFit() {
        return fit;
    }

    public void setFit(int fit) {
        this.fit = fit;
    }

    public String getDocumentation() {
        return documentation;
    }

    public void setDocumentation(String documentation) {
        this.documentation = documentation;
    }
}
