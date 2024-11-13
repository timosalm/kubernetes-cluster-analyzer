package com.vmware.tanzu.k8s_cluster_analyzer;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Property;
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
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@org.springframework.stereotype.Component
public class AnalyzerUtils {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerUtils.class);

    public static String generateSBom(String containerImage, List<RegistryCredentials> registryCredentials) throws IOException, InterruptedException, GenerateSBomExeption {
        for (RegistryCredentials creds : registryCredentials) {
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
        return classifications;
    }

    private static boolean isMacOs() {
        return System.getProperty("os.name").toLowerCase().contains("mac");
    }

    public static List<RegistryCredentials> getRelevantRegistryCredentials(String containerImage,
                                                                           List<RegistryCredentials> registryCredentials) {
        var relevantRegistryCredentials = registryCredentials.stream()
                .filter(credential -> containerImage.startsWith(credential.getUrl()))
                .sorted(Comparator.comparingInt((RegistryCredentials c) -> c.getUrl().length()).reversed())
                .collect(Collectors.toList());
        relevantRegistryCredentials.add(new RegistryCredentials("","",""));
        return relevantRegistryCredentials;
    }
}
