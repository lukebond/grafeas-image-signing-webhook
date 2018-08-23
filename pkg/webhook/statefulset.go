package webhook

import (
	"bufio"
	"bytes"
	"context"
	//"fmt"
	//grafeas "github.com/Grafeas/client-go/v1alpha1"
	"github.com/slok/kubewebhook/pkg/log"
	"github.com/slok/kubewebhook/pkg/observability/metrics"
	"github.com/slok/kubewebhook/pkg/webhook"
	"github.com/slok/kubewebhook/pkg/webhook/validating"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
)

// statefulSetValidator validates the definition against the Kubesec.io score.
type statefulSetValidator struct {
	grafeasUrl string
	logger   log.Logger
}

func (d *statefulSetValidator) Validate(_ context.Context, obj metav1.Object) (bool, validating.ValidatorResult, error) {
	kObj, ok := obj.(*appsv1beta1.StatefulSet)
	if !ok {
		d.logger.Errorf("received invalid StatefulSet object %v", obj)
		return false, validating.ValidatorResult{Valid: true}, nil
	}

	serializer := kjson.NewYAMLSerializer(kjson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)

	kObj.TypeMeta = metav1.TypeMeta{
		Kind:       "StatefulSet",
		APIVersion: "apps/v1",
	}

	err := serializer.Encode(kObj, writer)
	if err != nil {
		d.logger.Errorf("statefulset serialization failed %v", err)
		return false, validating.ValidatorResult{Valid: true}, nil
	}

	writer.Flush()

	d.logger.Infof("Scanning statefulset %s", kObj.Name)

	//result, err := kubesec.NewClient().ScanDefinition(buffer)
	//if err != nil {
	//	d.logger.Errorf("kubesec.io scan failed %v", err)
	//	return false, validating.ValidatorResult{Valid: true}, nil
	//}
	//if result.Error != "" {
	//	d.logger.Errorf("kubesec.io scan failed %v", result.Error)
	//	return false, validating.ValidatorResult{Valid: true}, nil
	//}

	//if result.Score < d.grafeasUrl {
	//	return true, validating.ValidatorResult{
	//		Valid:   false,
	//		Message: fmt.Sprintf("%s score is %d, statefulset minimum accepted score is %d", kObj.Name, result.Score, d.grafeasUrl),
	//	}, nil
	//}

	return false, validating.ValidatorResult{Valid: true}, nil
}

// NewStatefulSetWebhook returns a new statefulset validating webhook.
func NewStatefulSetWebhook(grafeasUrl string, mrec metrics.Recorder, logger log.Logger) (webhook.Webhook, error) {

	// Create validators.
	val := &statefulSetValidator{
		grafeasUrl: grafeasUrl,
		logger:   logger,
	}

	cfg := validating.WebhookConfig{
		Name: "grafeas-image-signing-statefulset",
		Obj:  &appsv1beta1.StatefulSet{},
	}

	return validating.NewWebhook(cfg, val, mrec, logger)
}
