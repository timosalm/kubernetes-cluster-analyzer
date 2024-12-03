package com.vmware.tanzu.k8s_cluster_analyzer;

import java.util.List;
import java.util.stream.Collectors;

public class AnalysisUiHelpers {

	private final Analysis analysis;

	public AnalysisUiHelpers(Analysis analysis) {
		this.analysis = analysis;
	}

	public List<List<?>> getContainerCategoriesChartData() {
		return analysis.getWorkloads().stream()
				.flatMap(w -> w.getContainers().stream())
				.flatMap(c -> c.getClassifications().stream())
				.map(c -> c == null ? "Not detected" : c.getType() + " - " + c.getSubType())
				.collect(Collectors.groupingBy(s -> s, Collectors.counting()))
				.entrySet().stream()
				.map(entry -> List.of(entry.getKey(), entry.getValue()))
				.collect(Collectors.toList());
	}

	public List<List<?>> getContainerProgrammingLanguagesChartData() {
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

	public List<List<?>> getContainerCompatibilityChartData() {
		return analysis.getWorkloads().stream().map(w -> w.getCompatibility().toString())
				.collect(Collectors.groupingBy(s -> s, Collectors.counting()))
				.entrySet().stream()
				.map(entry -> List.of(entry.getKey(), entry.getValue()))
				.collect(Collectors.toList());
	}

	public int getRowSpan(Workload workload) {
		return workload.getContainers().stream().map(this::getRowSpan).reduce(0, Integer::sum);
	}

	public int getRowSpan(Container container) {
		return Math.max(container.getClassifications().size(), 1);
	}

	public String getFormattedClassificationType(List<Classification> classifications, int index) {
		return getFormattedClassificationType(classifications.isEmpty() ? null : classifications.get(index));
	}

	public String getFormattedClassificationType(Classification classification) {
		var formattedType = new StringBuilder();
		if (classification != null) {
			if (classification.getType() != null) formattedType.append(classification.getType());
			if (classification.getSubType() != null) formattedType.append(" - ").append(classification.getSubType());
		} else {
			formattedType.append("Unknown");
		}
		return formattedType.toString();
	}

	public String getFormattedClassificationTechnology(Classification classification) {
		var formattedType = new StringBuilder();
		if (classification != null) {
			if (classification.getTechnology() != null) formattedType.append(classification.getTechnology());
			if (classification.getTechnologyVersion() != null) formattedType.append(" - ").append(classification.getTechnologyVersion());
		}
		return formattedType.toString();
	}

	public <T> T getFirstOrNull(List<T> list) {
		return list.isEmpty() ? null : list.getFirst();
	}
}
