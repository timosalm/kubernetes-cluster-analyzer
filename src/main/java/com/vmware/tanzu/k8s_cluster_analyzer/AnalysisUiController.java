package com.vmware.tanzu.k8s_cluster_analyzer;

import io.github.wimdeblauwe.htmx.spring.boot.mvc.HtmxResponse;
import io.github.wimdeblauwe.htmx.spring.boot.mvc.HxRequest;
import io.kubernetes.client.openapi.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Controller
public class AnalysisUiController {

    private final AnalysisService analysisService;
    private final AnalyzerConfig analyzerConfig;

    public AnalysisUiController(AnalysisService analysisService, AnalyzerConfig analyzerConfig) {
        this.analysisService = analysisService;
        this.analyzerConfig = analyzerConfig;
    }

    @GetMapping
    public String fetchUI(Model model) {
        model.addAttribute("analysisFormData", new AnalysisFormData());
        model.addAttribute("analyzerConfig", analyzerConfig);
        return "index";
    }

    @PostMapping("/analysis")
    public String analyze(@ModelAttribute AnalysisFormData analysisFormData)
            throws IOException, ApiException {
        var analysis = analysisService.analyze(analysisFormData.getKubeConfig().getResource(),
                analysisFormData.namespacesAsList(), analysisFormData.getExcludeNamespacesAsList(),
                analysisFormData.getValidatedRegistryCredentials(), analysisFormData.getUseSBom());
        return "redirect:analysis/%s".formatted(analysis.getId());
    }

    @GetMapping("/analysis/{id}")
    public String viewAnalysis(@PathVariable("id") UUID analysisId, Model model) {
        var analysis = analysisService.fetchAnalysis(analysisId);
        if (analysis == null) throw new ResourceNotFoundException();
        model.addAttribute("analysis", analysis);
        model.addAttribute("containerCategoriesChartData", getContainerCategoriesChartData(analysis));
        model.addAttribute("containerProgrammingLanguagesChartData", getContainerProgrammingLanguagesChartData(analysis));
        model.addAttribute("containerCompatibilityChartData", getContainerCompatibilityChartData(analysis));
        return "analysis";
    }

    @HxRequest
    @GetMapping("/analysis/{id}")
    @ResponseStatus
    public ModelAndView updateAnalysisView(@PathVariable("id") UUID analysisId, Model model, HtmxResponse.Builder htmxResponse) {
        var analysis = analysisService.fetchAnalysis(analysisId);
        if (analysis == null) throw new ResourceNotFoundException();

        model.addAttribute("analysis", analysis);
        model.addAttribute("containerCategoriesChartData", getContainerCategoriesChartData(analysis));
        model.addAttribute("containerProgrammingLanguagesChartData", getContainerProgrammingLanguagesChartData(analysis));
        model.addAttribute("containerCompatibilityChartData", getContainerCompatibilityChartData(analysis));

        var modelAndView = new ModelAndView("analysis :: analysisResult", "", model);
        if (analysis.getStatus() == Classification.Status.COMPLETED) {
            // Stop polling https://htmx.org/docs/#polling
            modelAndView.setStatus(HttpStatusCode.valueOf(286));
        } else {
            modelAndView.setStatus(HttpStatus.OK);
        }
        return modelAndView;
    }

    private List<List<?>> getContainerCategoriesChartData(Analysis analysis) {
        return analysis.getWorkloads().stream()
                .flatMap(w -> w.getContainers().stream())
                .flatMap(c -> c.getClassifications().stream())
                .map(c -> c == null ? "Not detected" : c.getType() + " - " + c.getSubType())
                .collect(Collectors.groupingBy(s -> s, Collectors.counting()))
                .entrySet().stream()
                .map(entry -> List.of(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());
    }

    private List<List<?>> getContainerProgrammingLanguagesChartData(Analysis analysis) {
        return analysis.getWorkloads().stream()
                .flatMap(w -> w.getContainers().stream())
                .flatMap(c -> c.getClassifications().stream())
                .filter(c -> c != null && c.getType().equals("Programming Language"))
                .map(c -> c.getType() + " - " + c.getSubType())
                .collect(Collectors.groupingBy(s -> s, Collectors.counting()))
                .entrySet().stream()
                .map(entry -> List.of(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());
    }

    private List<List<?>> getContainerCompatibilityChartData(Analysis analysis) {
        return analysis.getWorkloads().stream().map(w -> w.getCompatibility().toString())
                .collect(Collectors.groupingBy(s -> s, Collectors.counting()))
                .entrySet().stream()
                .map(entry -> List.of(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());
    }

    @GetMapping(
            value = "/analysis/{id}/workloads/{workloadId}/containers/{containerId}/sbom",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> fetchSBom(@PathVariable("id") UUID analysisId, @PathVariable("workloadId") UUID workloadId,
                                      @PathVariable("containerId") UUID containerId) {
        var sBom = analysisService.fetchSBom(containerId);
        if (sBom == null || sBom.isEmpty()) throw new ResourceNotFoundException();
        return ResponseEntity.ok(sBom);
    }
}
