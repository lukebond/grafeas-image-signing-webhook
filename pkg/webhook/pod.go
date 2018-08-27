package webhook

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	grafeas "github.com/Grafeas/client-go/v1alpha1"
	"github.com/slok/kubewebhook/pkg/log"
	"github.com/slok/kubewebhook/pkg/observability/metrics"
	"github.com/slok/kubewebhook/pkg/webhook"
	"github.com/slok/kubewebhook/pkg/webhook/validating"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
)

// podValidator validates the definition against the Kubesec.io score.
type podValidator struct {
	grafeasUrl string
	logger   log.Logger
}

func (d *podValidator) Validate(_ context.Context, obj metav1.Object) (bool, validating.ValidatorResult, error) {
	kObj, ok := obj.(*v1.Pod)
	if !ok {
		return false, validating.ValidatorResult{Valid: true}, nil
	}

	serializer := kjson.NewYAMLSerializer(kjson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)

	kObj.TypeMeta = metav1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}

	err := serializer.Encode(kObj, writer)
	if err != nil {
		d.logger.Errorf("pod serialization failed %v", err)
		return false, validating.ValidatorResult{Valid: true}, nil
	}

	writer.Flush()

	d.logger.Infof("Scanning pod %s", kObj.Name)
/*
  	admissionResponse := v1beta1.AdmissionResponse{Allowed: false}
	for _, container := range pod.Spec.Containers {
		// Retrieve all occurrences.
		// This call should be replaced by a filtered called based on
		// the container image under review.
		u := fmt.Sprintf("%s/%s", grafeasUrl, occurrencesPath)
		resp, err := http.Get(u)
		if err != nil {
			log.Println(err)
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			resp.Body.Close()
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Printf("non 200 status code: %d", resp.StatusCode)
			continue
		}

		occurrencesResponse := grafeas.ListOccurrencesResponse{}
		if err := json.Unmarshal(data, &occurrencesResponse); err != nil {
			log.Println(err)
			continue
		}

		// Find a valid signature for the given container image.
		match := false
		for _, occurrence := range occurrencesResponse.Occurrences {
			resourceUrl := occurrence.ResourceUrl
			signature := occurrence.Attestation.PgpSignedAttestation.Signature
			keyId := occurrence.Attestation.PgpSignedAttestation.PgpKeyId

			log.Printf("Container Image: %s", container.Image)
			log.Printf("ResourceUrl: %s", resourceUrl)
			log.Printf("Signature: %s", signature)
			log.Printf("KeyId: %s", keyId)

			if container.Image != strings.TrimPrefix(resourceUrl, "https://") {
				continue
			}

			match = true

			s, err := base64.StdEncoding.DecodeString(signature)
			if err != nil {
				log.Println(err)
				continue
			}

			publicKey := fmt.Sprintf("/etc/admission-controller/pubkeys/%s.pub", keyId)
			log.Printf("Using public key: %s", publicKey)

			f, err := os.Open(publicKey)
			if err != nil {
				log.Println(err)
				continue
			}

			block, err := armor.Decode(f)
			if err != nil {
				log.Println(err)
				continue
			}

			if block.Type != openpgp.PublicKeyType {
				log.Println("Not public key")
				continue
			}

			reader := packet.NewReader(block.Body)
			pkt, err := reader.Next()
			if err != nil {
				log.Println(err)
				continue
			}

			key, ok := pkt.(*packet.PublicKey)
			if !ok {
				log.Println("Not public key")
				continue
			}

			b, _ := clearsign.Decode(s)

			reader = packet.NewReader(b.ArmoredSignature.Body)
			pkt, err = reader.Next()
			if err != nil {
				log.Println(err)
				continue
			}

			sig, ok := pkt.(*packet.Signature)
			if !ok {
				log.Println("Not signature")
				continue
			}

			hash := sig.Hash.New()
			io.Copy(hash, bytes.NewReader(b.Bytes))

			err = key.VerifySignature(hash, sig)
			if err != nil {
				log.Println(err)

				message := fmt.Sprintf("Signature verification failed for container image: %s", container.Image)
				log.Printf(message)

				admissionResponse.Allowed = false
				admissionResponse.Result = &metav1.Status{
					Reason: metav1.StatusReasonInvalid,
					Details: &metav1.StatusDetails{
						Causes: []metav1.StatusCause{
							{Message: message},
						},
					},
				}
				goto done
			}

			log.Printf("Signature verified for container image: %s", container.Image)
			admissionResponse.Allowed = true
		}

		if !match {
			message := fmt.Sprintf("No matched signatures for container image: %s", container.Image)
			log.Printf(message)
			admissionResponse.Allowed = false
			admissionResponse.Result = &metav1.Status{
				Reason: metav1.StatusReasonInvalid,
				Details: &metav1.StatusDetails{
					Causes: []metav1.StatusCause{
						{Message: message},
					},
				},
			}
			goto done
		}
	}
*/

	//result, err := kubesec.NewClient().ScanDefinition(buffer)
	//if err != nil {
	//	d.logger.Errorf("kubesec.io scan failed %v", err)
	//	return false, validating.ValidatorResult{Valid: true}, nil
	//}
	//if result.Error != "" {
	//	d.logger.Errorf("kubesec.io scan failed %v", result.Error)
	//	return false, validating.ValidatorResult{Valid: true}, nil
	//}

	//if result.Score < d.minScore {
	//	return true, validating.ValidatorResult{
	//		Valid:   false,
	//		Message: fmt.Sprintf("%s score is %d, minimum accepted score is %d", kObj.Name, result.Score, d.minScore),
	//	}, nil
	//}

	return false, validating.ValidatorResult{Valid: true}, nil
}

// NewPodWebhook returns a new deployment validating webhook.
func NewPodWebhook(grafeasUrl string, mrec metrics.Recorder, logger log.Logger) (webhook.Webhook, error) {

	// Create validators.
	val := &podValidator{
		grafeasUrl: grafeasUrl,
		logger:   logger,
	}

	cfg := validating.WebhookConfig{
		Name: "grafeas-image-signing-pod",
		Obj:  &v1.Pod{},
	}

	return validating.NewWebhook(cfg, val, mrec, logger)
}
