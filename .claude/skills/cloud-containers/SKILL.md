---
name: cloud-containers
description: "Use this skill when the target uses AWS/Azure/GCP, when you find docker images on Docker Hub/GHCR, when subdomain enum surfaces *.s3.amazonaws.com / *.blob.core.windows.net / *.storage.googleapis.com, when fingerprint shows Kubernetes (10250/2379/etcd), when CI/CD endpoints are reachable (Jenkins, GitLab, GHA), or when IAM creds are spotted in JS bundles. Covers AWS/Azure/GCP/Docker/K8s misconfigurations and exploitation. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

# Cloud & Containers

Test cloud infrastructure and container environments for security misconfigurations and exploitation paths.

## Techniques

| Platform | Key Vectors |
|----------|-------------|
| **AWS** | S3 bucket exposure, IAM misconfig, metadata service, Lambda abuse |
| **Azure** | Blob storage, RBAC flaws, managed identity, App Service misconfig |
| **GCP** | Cloud Storage, service account keys, metadata server, IAM |
| **Docker** | Container escape, privileged mode, socket exposure, image vulnerabilities |
| **Kubernetes** | RBAC bypass, secret exposure, pod escape, API server access |

## Workflow

1. Enumerate cloud resources and services
2. Test IAM/RBAC configurations
3. Check storage and secrets exposure
4. Test container isolation and escape paths
5. Document findings with cloud-specific evidence

## Reference

- `reference/cloud-security.md` - Platform-specific attack guides (AWS, Azure, GCP, Docker, K8s)

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
