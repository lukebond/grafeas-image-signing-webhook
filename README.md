# grafeas-image-signing-webhook

This repo began as a fork from
[https://github.com/stefanprodan/kubesec-webhook.git](https://github.com/stefanprodan/kubesec-webhook.git).
All credit goes to Stefan for 99% of this codebase.

Kubernetes validating webhook admission controller that checks if images
have been signed in Grafeas.

### Install

Generate webhook configuration files with a new TLS certificate and CA
Bundle:

```bash
make certs
```

Deploy the admission controller and webhooks in the kubesec namespace
(requires Kubernetes 1.10 or newer):

```bash
make deploy
``` 

Enable grafeas-image-signing validation by adding this label:

```bash
kubectl label namespaces default grafeas-image-signing-validation=enabled
```

### Usage

Try to apply a privileged Deployment:

```bash
kubectl apply -f ./test/deployment.yaml

Error from server (InternalError): error when creating "./test/deployment.yaml": 
Internal error occurred: admission webhook "deployment.admission.kubesc.io" denied the request: 
deployment-test score is -30, deployment minimum accepted score is 0
```

Try to apply a privileged DaemonSet:

```bash
kubectl apply -f ./test/daemonset.yaml

Error from server (InternalError): error when creating "./test/daemonset.yaml": 
Internal error occurred: admission webhook "daemonset.admission.kubesc.io" denied the request: 
daemonset-test score is -30, daemonset minimum accepted score is 0
```

Try to apply a privileged StatefulSet:

```bash
kubectl apply -f ./test/statefulset.yaml

Error from server (InternalError): error when creating "./test/statefulset.yaml": 
Internal error occurred: admission webhook "statefulset.admission.kubesc.io" denied the request: 
statefulset-test score is -30, deployment minimum accepted score is 0
```

### Configuration

TODO
- configure URL of grafeas instance

You can set the minimum Kubesec.io score in `./deploy/webhook/yaml`:

```yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: kubesec-webhook
  labels:
    app: kubesec-webhook
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: kubesec-webhook
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8081"
    spec:
      containers:
        - name: kubesec-webhook
          image: stefanprodan/kubesec:0.1-dev
          imagePullPolicy: Always
          command:
            - ./kubesec
          args:
            - -tls-cert-file=/etc/webhook/certs/cert.pem
            - -tls-key-file=/etc/webhook/certs/key.pem
            - -min-score=0
          ports:
            - containerPort: 8080
            - containerPort: 8081
          volumeMounts:
            - name: webhook-certs
              mountPath: /etc/webhook/certs
              readOnly: true
      volumes:
        - name: webhook-certs
          secret:
            secretName: kubesec-webhook-certs
```

### Monitoring 

The admission controller exposes Prometheus RED metrics for each webhook a Grafana dashboard is available [here](https://grafana.com/dashboards/7088).

### Credits

Kudos to [Xabier](https://github.com/slok) for the awesome [kubewebhook library](https://github.com/slok/kubewebhook).  
