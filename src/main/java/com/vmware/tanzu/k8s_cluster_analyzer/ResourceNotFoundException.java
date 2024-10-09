package com.vmware.tanzu.k8s_cluster_analyzer;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value= HttpStatus.NOT_FOUND, reason="Resource not found")  // 404
public class ResourceNotFoundException extends RuntimeException {
}
