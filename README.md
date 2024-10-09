curl -XPOST -F "kubeconfig=@/Users/tsalm/Downloads/kubeconfig" -F "pageBottomMargin=50" http://localhost:8080/api/v1/analyses

Download trivy and add it to "src/main/resources/trivy"
If you are on an ARM Mac, download triva and put it in src/main/resources/trivy-mac-arm