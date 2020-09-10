/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	adcav1 "github.com/eu-evops/active-diretory-ca-k8s-operator/api/v1"
)

// ADCASigningRequestReconciler reconciles a ADCASigningRequest object
type ADCASigningRequestReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

func toDNSName(name string) string {
	pattern := regexp.MustCompile("[^\\d\\w]")
	return pattern.ReplaceAllLiteralString(name, "")
}

func toPem(c *x509.Certificate) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}

	return pem.EncodeToMemory(block)
}

// Reconcile is the main method called when resources are created/updated
// +kubebuilder:rbac:groups=adca.evops.eu,resources=adcasigningrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=adca.evops.eu,resources=adcasigningrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=configMaps,secrets,verbs=get;list;
func (r *ADCASigningRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {

	config := &corev1.ConfigMap{}
	err := r.Get(context.TODO(), types.NamespacedName{Name: "adca-config", Namespace: os.Getenv("WATCH_NAMESPACE")}, config)
	if err != nil {
		r.Log.Error(err, "Could not find Operator configuration, you need to provide adca-config")
		requeueAfter, _ := time.ParseDuration("1m")
		return reconcile.Result{RequeueAfter: requeueAfter, Requeue: true}, nil
	}

	adcaCredential := &corev1.Secret{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: config.Data["adcaCredentialSecretName"], Namespace: os.Getenv("WATCH_NAMESPACE")}, adcaCredential)
	if err != nil {
		r.Log.Error(err, "Could not find AD CA credentials secret")
		requeueAfter, _ := time.ParseDuration("1m")
		return reconcile.Result{RequeueAfter: requeueAfter, Requeue: true}, nil
	}

	_ = context.Background()
	_ = r.Log.WithValues("adca-signing-request", req.NamespacedName)

	certsrv := &Certsrv{
		Server:   config.Data["server"],
		Username: string(adcaCredential.Data["username"]),
		Password: string(adcaCredential.Data["password"]),
	}

	if err := certsrv.ValidateCredentials(); err != nil {
		r.Log.Error(err, "Could not authenticate with AD CA server")
		requeueAfter, _ := time.ParseDuration("1m")
		return reconcile.Result{RequeueAfter: requeueAfter}, nil
	}

	signingRequest := &adcav1.ADCASigningRequest{}
	r.Get(context.TODO(), req.NamespacedName, signingRequest)

	privateKey, reqID := certsrv.Submit(signingRequest.Spec.Domain)
	caCerts := certsrv.RetrieveCACerts()

	cert, err := certsrv.Retrieve(reqID)
	if err != nil {
		return reconcile.Result{}, err
	}

	certificateChain := []*x509.Certificate{}
	certificateChain = append(certificateChain, cert)
	certificateChain = append(certificateChain, caCerts...)

	privateKeyPemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPemBlock)

	certificateChainBytes := []byte{}

	for _, c := range certificateChain {
		certificateChainBytes = append(certificateChainBytes, toPem(c)...)
	}

	certBytes := toPem(cert)

	secretName := fmt.Sprintf("%s-tls", req.Name)
	secret := &corev1.Secret{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: req.NamespacedName.Namespace}, secret)
	if err != nil && errors.IsNotFound(err) {
		r.Log.Info("Not got the secret")

		secret.Namespace = req.NamespacedName.Namespace
		secret.Name = secretName
		secret.Type = "kubernetes.io/tls"

		secret.Data = map[string][]byte{
			"tls.crtChain": certificateChainBytes,
			"tls.crt":      certBytes,
			"tls.key":      privateKeyBytes,
		}

		for _, c := range caCerts {
			secret.Data[toDNSName(c.Subject.CommonName)] = toPem(c)
		}

		err = r.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}

		signingRequest.Status.Provisioned = true
		r.Status().Update(context.TODO(), signingRequest)
	} else {
		r.Log.Info("Got the secret")
		secret.Data["tls.crtChain"] = certificateChainBytes
		secret.Data["tls.crt"] = certBytes
		secret.Data["tls.key"] = privateKeyBytes
		for _, c := range caCerts {
			secret.Data[toDNSName(c.Subject.CommonName)] = toPem(c)
		}
		r.Update(context.TODO(), secret)
	}

	event := &corev1.Event{}
	event.Message = "Creating secret for my signing request"
	event.GenerateName = "event"
	event.Reason = "CreateTlsSecret"
	event.Type = "Normal"
	event.Namespace = req.NamespacedName.Namespace
	event.InvolvedObject.APIVersion = signingRequest.APIVersion
	event.InvolvedObject.Kind = signingRequest.Kind
	event.InvolvedObject.Name = signingRequest.Name
	event.InvolvedObject.Namespace = signingRequest.Namespace
	event.InvolvedObject.UID = signingRequest.UID

	event.LastTimestamp = v1.Now()

	err = r.Create(context.TODO(), event)
	if err != nil {
		r.Log.Error(err, "Error while creating an event")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager initiates k8s operator
func (r *ADCASigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	_, found := os.LookupEnv("WATCH_NAMESPACE")
	if !found {
		objRef := &schema.GroupResource{Group: "WATCH_NAMESPACE", Resource: "env"}
		return errors.NewNotFound(*objRef, "Failed to obtain WATCH_NAMESPACE environment variable")
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&adcav1.ADCASigningRequest{}).
		Complete(r)
}
