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
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@org.springframework.stereotype.Component
public class AnalyzerUtils {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerUtils.class);

    public static String generateSBom(String containerImage, List<RegistryCredentials> registryCredentials) throws IOException, InterruptedException, GenerateSBomExeption {

        var  relevantRegistryCredentials = registryCredentials.stream().filter(c -> containerImage.startsWith(c.getServer())).collect(Collectors.toCollection(ArrayList::new));
        relevantRegistryCredentials.add(new RegistryCredentials("","",""));

        for (RegistryCredentials creds : relevantRegistryCredentials) {
            var process =  runSyftProcess(containerImage, creds);

            var builder = new StringBuilder();
            try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    builder.append(line);
                }
            }

            var returnCode = process.waitFor();
            if (returnCode == 0) {
                return builder.toString();
            } else {
                log.warn("Syft failed for container {} with return code {} and error {}", containerImage, returnCode, builder);
            }
        }

        throw new GenerateSBomExeption(containerImage);
    }

    private static Process runSyftProcess(String containerImage, RegistryCredentials registryCredentials) throws IOException {
        var syftExecutable = new ClassPathResource(isMacOs() ? "syft/syft-mac-arm" : "syft/syft").getFile();
        var command = new ArrayList<String>();
        command.add(syftExecutable.getPath());
        command.add(containerImage);
        command.add("-o");
        command.add("cyclonedx-json");
        command.add("--quiet");

        var processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        processBuilder.environment().put("SYFT_REGISTRY_AUTH_AUTHORITY", registryCredentials.getServer());
        processBuilder.environment().put("SYFT_REGISTRY_AUTH_USERNAME", registryCredentials.getUsername());
        processBuilder.environment().put("SYFT_REGISTRY_AUTH_PASSWORD", registryCredentials.getPassword());
        return processBuilder.start();
    }

    public static List<Classification> classifySBom(String sBom, List<Classifier> classifiers) throws ParseException {
        var parsedSBom = new JsonParser().parse(sBom.getBytes(StandardCharsets.UTF_8));

        var relevantComponents = AnalyzerUtils.getDirectDependencies(parsedSBom);
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
