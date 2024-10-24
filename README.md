# Kubernetes Cluster Analyzer to Validate Compatibility of Workloads With Tanzu Application Service/Cloud Foundry 

The application requires a kubeconfig were the configuration is defined without any other tools like the aws CLI.
You can also provide container registry credentials if necessary. 

Neither the kubeconfig, nor the registry credentials will be stored!

## Prerequisites
- JDK version 21

## Local project setup

[Download the tar with the latest trivy release for Linux 64bit](https://github.com/aquasecurity/trivy/releases), unpack it, and move the executable to "src/main/resources/trivy/trivy".
(Optional) For local testing, ARM Mac is also supported. Download the trivy release for it and put it in "src/main/resources/trivy/trivy-mac-arm".

Download the latest trivy vulnerability databases.
```
(cd src/main/resources/trivy && ./trivy image --cache-dir . --download-db-only)
(cd src/main/resources/trivy && ./trivy image --cache-dir . --download-java-db-only)
```

## Run the application locally
```
./mvnw spring-boot:run
```
Open http://localhost:8080 in the browser

## Pushing the application to Tanzu Application Service/Cloud Foundry
```
./mvnw clean package
cf target -o ... -s ...
cf push
```