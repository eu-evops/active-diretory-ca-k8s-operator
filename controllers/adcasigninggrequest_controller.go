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
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	adcav1 "github.com/eu-evops/active-diretory-ca-k8s-operator/api/v1"
)

// ADCASigninggRequestReconciler reconciles a ADCASigninggRequest object
type ADCASigninggRequestReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=adca.evops.eu,resources=adcasigninggrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=adca.evops.eu,resources=adcasigninggrequests/status,verbs=get;update;patch
func (r *ADCASigninggRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("adcasigninggrequest", req.NamespacedName)

	certsrv := &Certsrv{
		Server: "axaxl.com",
	}
	if err := certsrv.ValidateCredentials(); err != nil {
		return reconcile.Result{}, err
	}

	ctrl.Log.Info("Reconciling state %s...")
	ctrl.Log.Info(req.String())

	signingRequest := &adcav1.ADCASigninggRequest{}
	r.Get(context.TODO(), req.NamespacedName, signingRequest)

	secretName := fmt.Sprintf("%s-tls", req.Name)
	secret := &corev1.Secret{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: req.NamespacedName.Namespace}, secret)
	if err != nil && errors.IsNotFound(err) {
		r.Log.Info("Not got the secret")

		secret.Namespace = req.NamespacedName.Namespace
		secret.Name = secretName
		secret.StringData = map[string]string{
			"Stan": req.Name,
		}
		err = r.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}

		signingRequest.Status.Provisioned = true
		r.Status().Update(context.TODO(), signingRequest)
	} else {
		r.Log.Info("Got the secret")
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

func (r *ADCASigninggRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&adcav1.ADCASigninggRequest{}).
		Complete(r)
}
