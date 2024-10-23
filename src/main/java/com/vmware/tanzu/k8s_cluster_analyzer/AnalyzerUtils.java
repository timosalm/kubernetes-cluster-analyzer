package com.vmware.tanzu.k8s_cluster_analyzer;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.cyclonedx.parsers.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public class AnalyzerUtils {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerUtils.class);

    public static String generateSBom(String containerImage, List<RegistryCredentials> registryCredentials) throws IOException, InterruptedException, TrivyException {
        var resultFile = File.createTempFile("trivy-results", ".json");
        resultFile.deleteOnExit();

        var trivyExecutable = new ClassPathResource(isMacOs() ? "trivy/trivy-mac-arm" : "trivy/trivy").getFile();

        var credentialsPrefix = registryCredentials.stream().filter(c -> containerImage.startsWith(c.getServer()))
                .map(c -> "TRIVY_USERNAME=%s TRIVY_PASSWORD=%s ".formatted(c.getUsername(), c.getPassword()))
                .findFirst().orElse("");
        var trivyCommand = "%s%s image --cache-dir %s --skip-db-update --skip-java-db-update --skip-check-update --format cyclonedx --scanners vuln --output %s --timeout 10m0s %s"
                .formatted(credentialsPrefix, trivyExecutable.getAbsolutePath(), trivyExecutable.getParent(), resultFile.getAbsolutePath(), containerImage);
        log.debug(trivyCommand);

        var processBuilder = new ProcessBuilder();
        processBuilder.command("sh", "-c", trivyCommand);
        var process = processBuilder.start();
        var returnCode = process.waitFor();

        String sbom;
        if (returnCode == 0) {
            sbom = Files.readString(resultFile.toPath(), StandardCharsets.UTF_8);
        } else {
            var consoleOutput = new StringBuilder();
            try (BufferedReader bufferedReader = process.inputReader();) {
                bufferedReader.lines().forEach(l -> consoleOutput.append(l).append("\n"));
            }
            resultFile.delete();
            throw new TrivyException(returnCode, consoleOutput.toString());
        }
        resultFile.delete();
        return sbom;
    }

    public static void analyzeSBom(Container container, List<Classifier> sBomClassifiers) throws ParseException {
        var parsedSBom = new JsonParser().parse(container.getSBom().getBytes(StandardCharsets.UTF_8));
        var classifications = classifySBom(parsedSBom, sBomClassifiers);
        container.addAll(classifications);
        var vulnerabilities = parsedSBom.getVulnerabilities().stream()
                .map(v -> v.getRatings().stream().map(Vulnerability.Rating::getSeverity)
                        .max(Comparator.comparingInt(Vulnerability.Rating.Severity::ordinal)))
                .flatMap(Optional::stream)
                .toList();
        container.setTotalCveCount(parsedSBom.getVulnerabilities().size());
        container.setCriticalCveCount(vulnerabilities.stream().filter(v -> v == Vulnerability.Rating.Severity.CRITICAL).toList().size());
        container.setHighCveCount(vulnerabilities.stream().filter(v -> v == Vulnerability.Rating.Severity.HIGH).toList().size());
    }

    public static List<Classification> classifySBom(Bom sBom, List<Classifier> classifiers) {
        var relevantComponents = AnalyzerUtils.getDirectDependencies(sBom);
        var matchedClassifiers = new ArrayList<Classifier>();
        var classifications = new ArrayList<Classification>();
        relevantComponents.forEach(component -> {
            for (Classifier classifier : classifiers) {
                if (Pattern.compile(classifier.regex()).matcher(component.getName()).matches()) {
                    if (!matchedClassifiers.contains(classifier)) {
                        matchedClassifiers.add(classifier);
                        classifications.add(Classification.from(classifier, component.getVersion()));
                    }
                }
            }
        });
        return classifications;
    }


    private static List<Component> getDirectDependencies(Bom sbom) {
        var sBomRef = sbom.getMetadata().getComponent().getBomRef();
        var directDependencies = sbom.getDependencies().stream().filter(d -> d.getRef().equals(sBomRef))
                .flatMap(d -> d.getDependencies().stream()).map(BomReference::getRef).toList();
        return sbom.getComponents().stream().filter(c -> directDependencies.contains(c.getBomRef())).toList();
    }

    private static boolean isMacOs() {
        return System.getProperty("os.name").toLowerCase().contains("mac");
    }
}
