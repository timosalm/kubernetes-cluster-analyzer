package com.vmware.tanzu.k8s_cluster_analyzer;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
public class Classification {

    public enum Status {
        PENDING("Pending"), COMPLETED("Completed"), FAILED("Failed");

        private final String label;
        Status(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return this.label;
        }
    }

    public enum Fit {
        No("No"), HIGH("High"), MEDIUM("Medium"), Low("Low"), NOT_RELEVANT("Not relevant"), Unknown("Unknown");

        private final String label;
        Fit(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return this.label;
        }
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    private String type;
    private String subType;
    private String technology;
    private Fit fit;
    private String documentation;
    private String technologyVersion;
    private String notes;

    public Classification(String type, String subType, String technology, Fit fit, String documentation, String technologyVersion, String notes) {
        this.notes = notes;
        this.type = type;
        this.subType = subType;
        this.technology = technology;
        this.fit = fit;
        this.documentation = documentation;
        this.technologyVersion = technologyVersion;
    }

    public Classification() {
    }

    public static Classification from(Classifier classifier) {
        return from(classifier, null);
    }

    public static Classification from(Classifier classifier, String technologyVersion) {
        return new Classification(classifier.type(), classifier.subType(), classifier.technology(), Fit.values()[classifier.fit()],
                classifier.documentation(), technologyVersion, classifier.notes());
    }

    public static List<Classification> deduplicate(List<Classification> classifications) {
        return classifications.stream()
                .collect(Collectors.groupingBy(classification ->
                                Arrays.asList(classification.getType(), classification.getSubType()),
                        Collectors.maxBy(Comparator.comparingInt(Classification::getPriority))
                ))
                .values().stream()
                .flatMap(Optional::stream)
                .collect(Collectors.toList());
    }

    private int getPriority() {
        int priority = 0;
        if (technology != null && !technology.isEmpty()) priority++;
        if (technologyVersion != null && !technologyVersion.isEmpty()) priority+=2;
        if (notes != null && !notes.isEmpty()) priority++;
        return priority;
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

    public Fit getFit() {
        return fit;
    }

    public void setFit(Fit fit) {
        this.fit = fit;
    }

    public String getDocumentation() {
        return documentation;
    }

    public void setDocumentation(String documentation) {
        this.documentation = documentation;
    }

    public String getTechnologyVersion() {
        return technologyVersion;
    }

    public void setTechnologyVersion(String technologyVersion) {
        this.technologyVersion = technologyVersion;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

}
