package com.vmware.tanzu.k8s_cluster_analyzer;

import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AnalysisFormData {

    private MultipartFile kubeConfig;
    private String namespaces;
    private String excludeNamespaces;
    private List<RegistryCredentials> registryCredentials;
    private Boolean useSBom;

    public AnalysisFormData(MultipartFile kubeConfig, String namespaces, String excludeNamespaces, List<RegistryCredentials> registryCredentials, Boolean useSBom) {
        this.kubeConfig = kubeConfig;
        this.namespaces = namespaces;
        this.excludeNamespaces = excludeNamespaces;
        this.registryCredentials = registryCredentials;
        this.useSBom = useSBom;
    }

    public AnalysisFormData() {
    }

    private static List<String> toList(String string) {
        if (string == null || string.isEmpty()) return new ArrayList<>();
        return Arrays.asList(string.split("\\s*,\\s*"));
    }

    public List<String> namespacesAsList() {
        return toList(namespaces);
    }

    public List<String> getExcludeNamespacesAsList() {
        return toList(excludeNamespaces);
    }

    public MultipartFile getKubeConfig() {
        return kubeConfig;
    }

    public void setKubeConfig(MultipartFile kubeConfig) {
        this.kubeConfig = kubeConfig;
    }

    public String getNamespaces() {
        return namespaces;
    }

    public void setNamespaces(String namespaces) {
        this.namespaces = namespaces;
    }

    public String getExcludeNamespaces() {
        return excludeNamespaces;
    }

    public void setExcludeNamespaces(String excludeNamespaces) {
        this.excludeNamespaces = excludeNamespaces;
    }

    public List<RegistryCredentials> getRegistryCredentials() {
        return registryCredentials;
    }

    public List<RegistryCredentials> getValidatedRegistryCredentials() {
        if (registryCredentials == null) {
            registryCredentials = new ArrayList<>();
        }

        return registryCredentials.stream().filter(credentials ->
                credentials.getUrl() != null && !credentials.getUrl().isEmpty() && credentials.getUrl().chars().noneMatch(Character::isWhitespace) &&
                        credentials.getUsername() != null && !credentials.getUsername().isEmpty() && credentials.getUsername().chars().noneMatch(Character::isWhitespace) &&
                        credentials.getPassword() != null && !credentials.getPassword().isEmpty() && credentials.getPassword().chars().noneMatch(Character::isWhitespace)
        ).toList();
    }

    public void setRegistryCredentials(List<RegistryCredentials> registryCredentials) {
        this.registryCredentials = registryCredentials;
    }

    public Boolean getUseSBom() {
        return this.useSBom == null ? false : this.useSBom;
    }

    public void setUseSBom(Boolean useSBom) {
        this.useSBom = useSBom;
    }
}
