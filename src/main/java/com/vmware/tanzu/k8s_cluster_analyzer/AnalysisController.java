package com.vmware.tanzu.k8s_cluster_analyzer;

import io.kubernetes.client.openapi.ApiException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URI;

import static com.vmware.tanzu.k8s_cluster_analyzer.AnalyzerUtils.toList;


@RequestMapping(AnalysisController.BASE_URI)
@RestController
public class AnalysisController {

    static final String BASE_URI = "/api/v1/analyses";

    private final AnalysisService analysisService;

    public AnalysisController(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    @PostMapping
    public ResponseEntity<Analysis> analyze(@RequestParam("kubeconfig") MultipartFile kubeConfig,
                                            @RequestParam(required = false, defaultValue = "") String namespaces,
                                            @RequestParam(required = false, defaultValue = "") String excludeNamespaces)
            throws IOException, ApiException {
        var analysis = analysisService.analyze(kubeConfig.getResource(), toList(namespaces), toList(excludeNamespaces));

        final URI analysisUri = URI.create(String.format("%s/%s", BASE_URI, analysis.getId()));
        return ResponseEntity.created(analysisUri).body(analysis);
    }
}
