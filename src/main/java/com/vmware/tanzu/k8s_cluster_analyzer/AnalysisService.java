package com.vmware.tanzu.k8s_cluster_analyzer;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.AppsV1Api;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1StatefulSet;
import io.kubernetes.client.util.ClientBuilder;
import io.kubernetes.client.util.KubeConfig;
import org.cyclonedx.exception.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

@Service
public class AnalysisService {

    private static final Logger log = LoggerFactory.getLogger(AnalysisService.class);

    private final Semaphore trivyProcessLock = new Semaphore(1);
    private final Semaphore dbConnectionPoolLock = new Semaphore(1);
    private final AnalyzerConfig analyzerConfig;
    private final AnalysisRepository analysisRepository;
    private final ContainerRepository containerRepository;
    private final ApplicationEventPublisher publisher;

    public AnalysisService(AnalyzerConfig analyzerConfig, AnalysisRepository analysisRepository, ContainerRepository containerRepository, ApplicationEventPublisher publisher) {
        this.analyzerConfig = analyzerConfig;
        this.analysisRepository = analysisRepository;
        this.containerRepository = containerRepository;
        this.publisher = publisher;
    }

    public Analysis fetchAnalysis(UUID analysisId) {
        return analysisRepository.findById(analysisId).orElse(null);
    }

    public String fetchSBom(UUID containerId) {
        return containerRepository.findById(containerId).map(Container::getSBom).orElse(null);
    }

    public Analysis analyze(Resource kubeConfig, List<String> namespaces, List<String> excludeNamespaces,
                            List<RegistryCredentials> registryCredentials, boolean useSBom) throws IOException, ApiException {
        var config = KubeConfig.loadKubeConfig(new InputStreamReader(kubeConfig.getInputStream()));
        var kubernetesClient = ClientBuilder.kubeconfig(config).build();

        var workloads = fetchWorkloads(kubernetesClient, namespaces, excludeNamespaces);
        log.info("Found {} workloads for analysis", workloads.size());
        workloads.forEach(workload -> {
            workload.classifyByContainerImageNames(analyzerConfig);
            if (!useSBom) {
                workload.getContainers().forEach(container -> container.setStatus(Classification.Status.COMPLETED));
            }
        });
        var analysis = new Analysis(config.getCurrentContext(), workloads);
        analysisRepository.save(analysis);
        log.info("Analysis created with id {} for context {}", analysis.getId(), analysis.getKubernetesContext());

        if (useSBom) {
            workloads.forEach(workload -> {
                workload.getUnclassifiedContainers().forEach(container -> {
                    log.info("Published SBOM analysis event for workload {}/{} container {}",
                            workload.getNamespace(), workload.getName(), container.getImage());
                    publisher.publishEvent(new ContainerSBomAnalysisEvent(analysis, workload, container, registryCredentials));
                });
            });
        }
        return analysis;
    }

    @Async
    @EventListener
    protected void onContainerSBomAnalysisEvent(ContainerSBomAnalysisEvent event)  {
        var container = event.getContainer();
        var workload = event.getWorkload();
        log.info("Received SBOM analysis event for workload {}/{} container {}", workload.getNamespace(),
                workload.getName(), container.getImage());
        String sBom = null;
        try {
            log.info("Starting to create SBOM for workload {}/{} container {}", workload.getNamespace(),
                    workload.getName(), container.getImage());
            sBom = AnalyzerUtils.generateSBom(container.getImage(), event.getRegistryCredentials());
            log.info("SBOM creation finished for workload {}/{} container {}", workload.getNamespace(),
                    workload.getName(), container.getImage());
        } catch (Exception e) {
            log.warn("SBOM generation failed for workload {}/{} container {}", workload.getNamespace(),
                    workload.getName(), container.getImage());
            container.setStatus(Classification.Status.FAILED);
            container.setErrorMessage("SBOM generation failed");
        }

        if (sBom != null) {
            container.setSBom(sBom);
            try {
                AnalyzerUtils.analyzeSBom(container, analyzerConfig.getSbomClassifiers());
                log.info("Analysis based on SBOM for workload finished {}/{} container {}", workload.getNamespace(),
                        workload.getName(), container.getImage());
                container.setStatus(Classification.Status.COMPLETED);
            } catch (Exception e) {
                log.warn("Unable to parse SBOM for workload {}/{} container {}", workload.getNamespace(), workload.getName(),
                        container.getImage());
                container.setStatus(Classification.Status.FAILED);
                container.setErrorMessage("Unable to parse SBOM");
            }
        }


        containerRepository.save(container);
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
