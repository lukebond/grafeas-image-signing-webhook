---
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: grafeas-image-signing-webhook
  labels:
    app: grafeas-image-signing-webhook
    kind: validator
webhooks:
  - name: deployment.admission.grafeas-image-signing-webhook
    clientConfig:
      service:
        name: grafeas-image-signing-webhook
        namespace: default
        path: "/deployment"
      caBundle: CA_BUNDLE
    rules:
      - operations:
        - CREATE
        - UPDATE
        apiGroups:
        - apps
        - extensions
        apiVersions:
        - "*"
        resources:
        - deployments
    failurePolicy: Fail
    namespaceSelector:
      matchLabels:
        grafeas-image-signing-validation: enabled
  - name: daemonset.admission.grafeas-image-signing-webhook
    clientConfig:
      service:
        name: grafeas-image-signing-webhook
        namespace: default
        path: "/daemonset"
      caBundle: CA_BUNDLE
    rules:
      - operations:
        - CREATE
        - UPDATE
        apiGroups:
        - apps
        - extensions
        apiVersions:
        - "*"
        resources:
        - daemonsets
    failurePolicy: Fail
    namespaceSelector:
      matchLabels:
        grafeas-image-signing-validation: enabled
  - name: statefulset.admission.grafeas-image-signing-webhook
    clientConfig:
      service:
        name: grafeas-image-signing-webhook
        namespace: default
        path: "/statefulset"
      caBundle: CA_BUNDLE
    rules:
      - operations:
        - CREATE
        apiGroups:
        - apps
        apiVersions:
        - "*"
        resources:
        - statefulsets
    failurePolicy: Fail
    namespaceSelector:
      matchLabels:
        grafeas-image-signing-validation: enabled
