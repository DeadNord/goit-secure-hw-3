package k8s

deny[msg] {
  input.kind == "Deployment"
  input.metadata.name == "user-api"
  not input.spec.template.spec.containers[_].securityContext.runAsNonRoot
  msg := "Deployment: container має мати securityContext.runAsNonRoot=true"
}

deny[msg] {
  input.kind == "Deployment"
  input.metadata.name == "user-api"
  not input.spec.template.spec.containers[_].securityContext.readOnlyRootFilesystem
  msg := "Deployment: container має мати securityContext.readOnlyRootFilesystem=true"
}

deny[msg] {
  input.kind == "Deployment"
  input.metadata.name == "user-api"
  input.spec.template.spec.containers[_].securityContext.allowPrivilegeEscalation != false
  msg := "Deployment: container має мати allowPrivilegeEscalation=false"
}

deny[msg] {
  input.kind == "Deployment"
  input.metadata.name == "user-api"
  not input.spec.template.spec.containers[_].readinessProbe
  msg := "Deployment: має бути readinessProbe (сигнал готовності)"
}

deny[msg] {
  input.kind == "Deployment"
  input.metadata.name == "user-api"
  # заборона plaintext secret у env.value
  some c
  some e
  c := input.spec.template.spec.containers[_]
  e := c.env[_]
  e.value
  msg := "Deployment: заборонено env.value (plaintext); використовуйте Vault CSI/ExternalSecrets"
}

deny[msg] {
  input.kind == "Deployment"
  input.metadata.name == "user-api"
  not has_vault_csi
  msg := "Deployment: має використовувати secrets-store.csi (Vault CSI) як сигнал secret management"
}

has_vault_csi {
  some v
  v := input.spec.template.spec.volumes[_]
  v.csi.driver == "secrets-store.csi.k8s.io"
}

deny[msg] {
  input.kind == "SecretProviderClass"
  not input.spec.provider
  msg := "SecretProviderClass: provider має бути заданий"
}
