package com.vmware.tanzu.k8s_cluster_analyzer;

import org.cyclonedx.exception.ParseException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@SpringBootTest
class K8sClusterAnalyzerApplicationTests {

	@Test
	void contextLoads() {
	}

	@Disabled
	@Test
	void sbom_analysis() throws IOException, ParseException {
		var resource = new ClassPathResource("sbom.json");
		var relevantComponents = AnalyzerUtils.getDirectDependencies(new String(resource.getContentAsByteArray(), StandardCharsets.UTF_8));
		System.out.println(relevantComponents.size());

		var isJava = relevantComponents.stream().anyMatch(c -> c.getName().contains("java"));
		var isJvm = relevantComponents.stream().anyMatch(c -> c.getName().contains("jvm"));
		var isTomcat = relevantComponents.stream().anyMatch(c -> c.getName().contains("tomcat"));
		var isSpringFramework = relevantComponents.stream().anyMatch(c -> c.getName().contains("spring-framework"));
		var isSpringBoot = relevantComponents.stream().anyMatch(c -> c.getName().contains("spring-boot"));
	}

}
