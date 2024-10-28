# Kubernetes Cluster Analyzer to Validate Compatibility of Workloads With Tanzu Application Service/Cloud Foundry 

The application requires a kubeconfig were the configuration is defined without any other tools like the aws CLI.
You can also provide container registry credentials if necessary. 

Neither the kubeconfig, nor the registry credentials will be stored!

## Prerequisites
- JDK version 21

## Setup

[Download the tar with the latest trivy release for Linux 64bit](https://github.com/aquasecurity/trivy/releases), unpack it, and move the executable to "src/main/resources/trivy/trivy".
(Optional) For local testing, ARM Mac is also supported. Download the trivy release for it and put it in "src/main/resources/trivy/trivy-mac-arm".

### Run the application locally

Start the trivy server component
```
trivy server --listen 0.0.0.0:8081
```

Run the applicatio.
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