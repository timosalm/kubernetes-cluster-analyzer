package com.vmware.tanzu.k8s_cluster_analyzer;

import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1PodTemplateSpec;
import io.kubernetes.client.openapi.models.V1StatefulSet;
import io.kubernetes.client.openapi.models.V1Volume;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import org.cyclonedx.exception.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Entity
public class Workload {

    private static final Logger log = LoggerFactory.getLogger(Workload.class);

    @Id
    private UUID id;
    private String name;
    private String namespace;
    private Type type;
    private int replicas;
    private boolean hasPvc;
    private boolean isManagedByHelm;
    @OneToMany(cascade = {CascadeType.ALL})
    private List<Container> containers;


    public Workload(String name, String namespace, Type type, int replicas, boolean hasPvc,
                    boolean isManagedByHelm, List<Container> containers) {
        this.id = UUID.randomUUID();
        this.name = name;
        this.namespace = namespace;
        this.type = type;
        this.replicas = replicas;
        this.hasPvc = hasPvc;
        this.isManagedByHelm = isManagedByHelm;
        this.containers = containers;
    }

    public Workload() {
    }

    public enum Type {
        DEPLOYMENT, STATEFUL_SET
    }

    public void analyze(AnalyzerConfig analyzerConfig) {
        containers.forEach(container -> {
            var classification = classify(container.getName(), analyzerConfig.getContainerNameClassifiers());
            container.addClassification(classification);
        });

        getUnclassifiedContainers().forEach(container -> {
            try {
                var sBom = AnalyzerUtils.generateSBom(container.getImage());
                container.setSBom(sBom);
                var classifications = classifySBom(sBom, analyzerConfig.getSbomClassifiers());
                container.setClassifications(classifications);
            } catch (IOException | InterruptedException | ParseException e) {
                log.warn("Unable to generate SBom for container %s".formatted(container.getImage()), e);
            }
        });
    }

    private Classification classify(String containerName, List<Classifier> classifiers) {
        for (Classifier classifier : classifiers) {
            if (Pattern.compile(classifier.regex()).matcher(containerName).matches()) {
                return Classification.from(classifier);
            }
        }
        return null;
    }

    private List<Classification> classifySBom(String sBom, List<Classifier> classifiers) throws ParseException {
        var relevantComponents = AnalyzerUtils.getDirectDependencies(sBom);
        var matchedClassifiers = new ArrayList<Classifier>();
        relevantComponents.forEach(component -> {
            for (Classifier classifier : classifiers) {
                if (Pattern.compile(classifier.regex()).matcher(component.getName()).matches()) {
                    if (!matchedClassifiers.contains(classifier)) {
                        matchedClassifiers.add(classifier);
                    }
                }
            }
        });
        return matchedClassifiers.stream().map(Classification::from).toList();
    }

    private List<Container> getUnclassifiedContainers() {
        return containers.stream().filter(c -> c.getClassifications().isEmpty()).toList();
    }

    public static Workload from(V1Deployment deployment) {
        var metadata = deployment.getMetadata();
        var spec = deployment.getSpec();
        return new Workload(metadata.getName(), metadata.getNamespace(), Workload.Type.DEPLOYMENT, spec.getReplicas(),
                hasPvc(spec.getTemplate().getSpec().getVolumes()), isManagedByHelm(metadata),
                containerImagesFrom(spec.getTemplate()));
    }

    public static Workload from(V1StatefulSet statefulSet) {
        var metadata = statefulSet.getMetadata();
        var spec = statefulSet.getSpec();
        return new Workload(metadata.getName(), metadata.getNamespace(), Type.STATEFUL_SET, spec.getReplicas(),
                hasPvc(spec.getTemplate().getSpec().getVolumes()), isManagedByHelm(metadata),
                containerImagesFrom(spec.getTemplate()));
    }

    private static boolean hasPvc(List<V1Volume> volumes) {
        if (volumes == null || volumes.isEmpty()) return false;
        return volumes.stream().anyMatch(v -> v.getPersistentVolumeClaim() != null);
    }

    private static boolean isManagedByHelm(V1ObjectMeta metadata) {
        var labels = metadata.getLabels();
        if (labels == null || labels.isEmpty()) return false;
        return labels.getOrDefault("app.kubernetes.io/managed-by", "").equalsIgnoreCase("Helm") ||
                labels.containsKey("helm.sh/chart");
    }

    private static List<Container> containerImagesFrom(V1PodTemplateSpec template) {
        return  template.getSpec().getContainers().stream().map(Container::from).toList();
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

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public int getReplicas() {
        return replicas;
    }

    public void setReplicas(int replicas) {
        this.replicas = replicas;
    }

    public boolean isHasPvc() {
        return hasPvc;
    }

    public void setHasPvc(boolean hasPvc) {
        this.hasPvc = hasPvc;
    }

    public boolean isManagedByHelm() {
        return isManagedByHelm;
    }

    public void setManagedByHelm(boolean managedByHelm) {
        isManagedByHelm = managedByHelm;
    }

    public List<Container> getContainers() {
        return containers;
    }

    public void setContainers(List<Container> containers) {
        this.containers = containers;
    }
}