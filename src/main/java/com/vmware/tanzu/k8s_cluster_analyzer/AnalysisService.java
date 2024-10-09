package com.vmware.tanzu.k8s_cluster_analyzer;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.AppsV1Api;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1Namespace;
import io.kubernetes.client.openapi.models.V1StatefulSet;
import io.kubernetes.client.util.ClientBuilder;
import io.kubernetes.client.util.KubeConfig;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.function.ThrowingFunction;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

@Service
public class AnalysisService {

    private final AnalyzerConfig analyzerConfig;
    private final AnalysisRepository analysisRepository;
    private final ContainerRepository containerRepository;

    public AnalysisService(AnalyzerConfig analyzerConfig, AnalysisRepository analysisRepository, ContainerRepository containerRepository) {
        this.analyzerConfig = analyzerConfig;
        this.analysisRepository = analysisRepository;
        this.containerRepository = containerRepository;
    }

    public Analysis fetchAnalysis(UUID analysisId) {
        return analysisRepository.findById(analysisId).orElse(null);
    }

    public String fetchSBom(UUID containerId) {
        return containerRepository.findById(containerId).map(Container::getSBom).orElse(null);
    }

    public Analysis analyze(Resource kubeConfig, List<String> namespaces, List<String> excludeNamespaces) throws IOException, ApiException {
        var config = KubeConfig.loadKubeConfig(new InputStreamReader(kubeConfig.getInputStream()));
        var kubernetesClient = ClientBuilder.kubeconfig(config).build();

        var workloads = fetchWorkloads(kubernetesClient, namespaces, excludeNamespaces);
        workloads.forEach(workload -> {
            workload.analyze(analyzerConfig);
        });

        var analysis = new Analysis(config.getCurrentContext(), workloads);
        analysisRepository.save(analysis);
        return analysis;
    }

    private List<Workload> fetchWorkloads(ApiClient kubernetesClient, List<String> namespaces, List<String> excludeNamespaces)
            throws ApiException {
        List<V1Deployment> deployments;
        List<V1StatefulSet> statefulSets;
        var appsApi = new AppsV1Api(kubernetesClient);
        if (namespaces == null || namespaces.isEmpty()) {
            deployments = appsApi.listDeploymentForAllNamespaces().execute().getItems();
            statefulSets = appsApi.listStatefulSetForAllNamespaces().execute().getItems();
        } else {
            deployments =  new ArrayList<>();
            statefulSets = new ArrayList<>();
            var coreApi = new CoreV1Api(kubernetesClient);
            var availableNamespaces = coreApi.listNamespace().execute().getItems().stream()
                    .map(n -> n.getMetadata().getName()).toList();
            for (var namespace : namespaces.stream().filter(availableNamespaces::contains).toList()) {
                deployments.addAll(appsApi.listNamespacedDeployment(namespace).execute().getItems());
                statefulSets.addAll(appsApi.listNamespacedStatefulSet(namespace).execute().getItems());
            }
        }

        var deploymentWorkloads = deployments.stream().map(Workload::from).toList();
        var statefulSetWorkloads = statefulSets.stream().map(Workload::from).toList();
        return Stream.concat(deploymentWorkloads.stream(), statefulSetWorkloads.stream())
                .filter(w -> !excludeNamespaces.contains(w.getNamespace())).toList();
    }
}
