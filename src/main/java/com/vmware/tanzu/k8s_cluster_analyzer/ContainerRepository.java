package com.vmware.tanzu.k8s_cluster_analyzer;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ContainerRepository extends ListCrudRepository<Container, UUID> {

}