package com.vmware.tanzu.k8s_cluster_analyzer;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Property;
import org.cyclonedx.parsers.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.testcontainers.utility.DockerImageName;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@org.springframework.stereotype.Component
public class AnalyzerUtils {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerUtils.class);

    public static String generateSBom(String containerImageTag, List<RegistryCredentials> registryCredentials) throws IOException, InterruptedException, GenerateSBomExeption {
        validateIsSafeForUseInCommand(containerImageTag);

        for (RegistryCredentials creds : registryCredentials) {
            var process =  runSyftProcess(containerImageTag, creds);

            var consoleOutput = new StringBuilder();
            try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    consoleOutput.append(line);
                }
            }

            var returnCode = process.waitFor();
            if (returnCode == 0) {
                return consoleOutput.toString();
            } else {
                log.warn("Syft failed for container {} with return code {} and message {}", containerImageTag, returnCode, consoleOutput);
            }
        }

        throw new GenerateSBomExeption("SBOM generation failed for container " + containerImageTag);
    }

    private static Process runSyftProcess(String containerImageTag, RegistryCredentials registryCredentials) throws IOException {
        var syftExecutable = new ClassPathResource(isMacOs() ? "syft/syft-mac-arm" : "syft/syft").getFile();
        var processBuilder = new ProcessBuilder(syftExecutable.getPath(), containerImageTag, "-o", "cyclonedx-json", "--quiet");
        processBuilder.redirectErrorStream(true);
        processBuilder.environment().put("SYFT_REGISTRY_AUTH_AUTHORITY", registryCredentials.getServer());
        processBuilder.environment().put("SYFT_REGISTRY_AUTH_USERNAME", registryCredentials.getUsername());
        processBuilder.environment().put("SYFT_REGISTRY_AUTH_PASSWORD", registryCredentials.getPassword());
        return processBuilder.start();
    }

    private static void validateIsSafeForUseInCommand(String containerImageTag) throws GenerateSBomExeption {
        var dockerImageName  = DockerImageName.parse(containerImageTag);
        try {
            dockerImageName.assertValid();
        } catch (Exception e) {
            throw new GenerateSBomExeption("Invalid container image tag format " + containerImageTag);
        }
    }

    public static List<Classification> classifySBom(String sBom, List<Classifier> classifiers) throws ParseException {
        var parsedSBom = new JsonParser().parse(sBom.getBytes(StandardCharsets.UTF_8));

        var matchedClassifiers = new ArrayList<Classifier>();
        var classifications = new ArrayList<Classification>();
        parsedSBom.getComponents().forEach(component -> {
            var detectedLanguage = component.getProperties().stream()
                    .filter(p -> p.getName().equals("syft:package:language"))
                    .map(Property::getValue).findFirst().orElse("");
            for (Classifier classifier : classifiers) {
                if (!matchedClassifiers.contains(classifier)) {
                    var pattern = Pattern.compile(classifier.regex());
                    if (pattern.matcher(component.getName()).matches()) {
                        matchedClassifiers.add(classifier);
                        classifications.add(Classification.from(classifier, component.getVersion()));
                    } else if (pattern.matcher(detectedLanguage).matches()) {
                        matchedClassifiers.add(classifier);
                        classifications.add(Classification.from(classifier, null));
                    }
                }
            }
        });
        return Classification.deduplicate(classifications);
    }

    private static boolean isMacOs() {
        return System.getProperty("os.name").toLowerCase().contains("mac");
    }

    public static List<RegistryCredentials> getRelevantRegistryCredentials(String containerImageTag,
                                                                           List<RegistryCredentials> registryCredentials) {
        var relevantRegistryCredentials = registryCredentials.stream()
                .filter(credential -> containerImageTag.startsWith(credential.getUrl()))
                .sorted(Comparator.comparingInt((RegistryCredentials c) -> c.getUrl().length()).reversed())
                .collect(Collectors.toList());
        relevantRegistryCredentials.add(new RegistryCredentials("","",""));
        return relevantRegistryCredentials;
    }
}
