package com.vmware.tanzu.k8s_cluster_analyzer;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.cyclonedx.parsers.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.io.ClassPathResource;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@org.springframework.stereotype.Component
public class AnalyzerUtils implements ApplicationContextAware {

    private static String trivyServerUrl;

    private static final Logger log = LoggerFactory.getLogger(AnalyzerUtils.class);

    public static String generateSBom(String containerImage, List<RegistryCredentials> registryCredentials) throws IOException, InterruptedException, TrivyException {
        var resultFile = File.createTempFile("trivy-results", ".json");
        resultFile.deleteOnExit();

       var process =  runTrivyProcess(containerImage, registryCredentials, resultFile);
       var returnCode = process.waitFor();

        String sbom;
        if (returnCode == 0) {
            sbom = Files.readString(resultFile.toPath(), StandardCharsets.UTF_8);
        } else {
            resultFile.delete();
            throw new TrivyException(returnCode);
        }
        resultFile.delete();
        return sbom;
    }

    private static Process runTrivyProcess(String containerImage, List<RegistryCredentials> registryCredentials, File resultFile) throws IOException {
        var trivyExecutable = new ClassPathResource(isMacOs() ? "trivy/trivy-mac-arm" : "trivy/trivy").getFile();
        var command = new ArrayList<String>();
        command.add(trivyExecutable.getPath());
        command.add("image");
        command.add("--server");
        command.add(trivyServerUrl);
        command.add("--format");
        command.add("cyclonedx");
        command.add("--scanners");
        command.add("vuln");
        command.add("--output");
        command.add(resultFile.getAbsolutePath());
        command.add(containerImage);

        var processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        var  relevantRegistryCredentials = registryCredentials.stream().filter(c -> containerImage.startsWith(c.getServer())).toList();
        if (!relevantRegistryCredentials.isEmpty()) {
            String usernamesString = relevantRegistryCredentials.stream().map(RegistryCredentials::getUsername)
                    .collect(Collectors.joining (","));
            String passwordString = relevantRegistryCredentials.stream().map(RegistryCredentials::getPassword)
                    .collect(Collectors.joining (","));
            processBuilder.environment().put("TRIVY_USERNAME", usernamesString);
            processBuilder.environment().put("TRIVY_PASSWORD", passwordString);
        }

        var process = processBuilder.start();

        try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("unable to find the specified image")) {
                    log.warn("Terminating Trivy process due to error output: " + line);
                    process.destroy();
                    break;
                }
            }
        }

        return process;
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

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        trivyServerUrl = applicationContext.getEnvironment().getProperty("analyzer.trivy-server-url");
    }
}
