package com.vmware.tanzu.k8s_cluster_analyzer;

public class RegistryCredentials {

    public String server;
    public String username;
    public String password;

    public RegistryCredentials() {
    }

    public RegistryCredentials(String server, String username, String password) {
        this.server = server;
        this.username = username;
        this.password = password;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
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
}
