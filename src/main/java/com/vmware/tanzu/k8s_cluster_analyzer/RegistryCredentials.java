package com.vmware.tanzu.k8s_cluster_analyzer;

public class RegistryCredentials {

    private String url;
    private String username;
    private String password;

    public RegistryCredentials() {
    }

    public RegistryCredentials(String url, String username, String password) {
        setUrl(url);
        this.username = username;
        this.password = password;
    }

    public String getServer() {
        if (url == null || url.isEmpty()) return "";
        return url.split("/")[0];
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url != null ? url.replace("http://", "").replace("https://", "") : null;
    }
}
