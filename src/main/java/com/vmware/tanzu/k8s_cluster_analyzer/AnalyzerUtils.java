package com.vmware.tanzu.k8s_cluster_analyzer;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SequencedCollection;

public class AnalyzerUtils {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerUtils.class);

    public static List<String> toList(String string) {
        if (string == null || string.isEmpty()) return new ArrayList<>();
        return Arrays.asList(string.split("\\s*,\\s*"));
    }

    public static String generateSBom(String containerImage) throws IOException, InterruptedException {
        var resultFile = File.createTempFile("trivy-results", ".json");
        resultFile.deleteOnExit();

        var trivyPath = new ClassPathResource(isMacOs() ? "trivy-mac-arm" : "trivy").getFile().getAbsolutePath();
        var trivyCommand = "%s image --format cyclonedx --scanners vuln --output %s %s"
                .formatted(trivyPath, resultFile.getAbsolutePath(), containerImage);
        log.debug(trivyCommand);

        var processBuilder = new ProcessBuilder();
        processBuilder.command("sh", "-c", trivyCommand);
        var process = processBuilder.start();
        var returnCode = process.waitFor();
        if (returnCode != 0) {
            log.info("Generation of SBOM with Trivy failed. Return code: " + returnCode);
            return null;
        }

        /*
        var result = new StringBuilder();
        try (BufferedReader bufferedReader = process.inputReader();) {
            bufferedReader.lines().forEach(l -> result.append(l).append("\n"));
        }
        */

        var sbom = Files.readString(resultFile.toPath(), StandardCharsets.UTF_8);
        resultFile.delete();
        return sbom;
    }

    public static List<Component> getDirectDependencies(String sBom) throws ParseException {
        var sbom = new JsonParser().parse(sBom.getBytes(StandardCharsets.UTF_8));

        var sBomRef = sbom.getMetadata().getComponent().getBomRef();
        var directDependencies = sbom.getDependencies().stream().filter(d -> d.getRef().equals(sBomRef))
                .flatMap(d -> d.getDependencies().stream()).map(BomReference::getRef).toList();
        return sbom.getComponents().stream().filter(c -> directDependencies.contains(c.getBomRef())).toList();
    }

    private static boolean isMacOs() {
        return System.getProperty("os.name").toLowerCase().contains("mac");
    }
}
