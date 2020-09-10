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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	PKCS7 "go.mozilla.org/pkcs7"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	adcav1 "github.com/eu-evops/active-diretory-ca-k8s-operator/api/v1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var testServer *httptest.Server
var testServerHandler *TestServerHandler

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

type TestRequest struct {
	request *http.Request
	body    []byte
}

type TestServerHandler struct {
	requestURLs []string
	requests    map[string]*TestRequest
}

func (h *TestServerHandler) addRequest(r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	h.requests[r.URL.RequestURI()] = &TestRequest{
		request: r,
		body:    body,
	}
	h.requestURLs = append(h.requestURLs, r.URL.RequestURI())
}

func (h *TestServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.addRequest(r)
	fmt.Fprintf(os.Stderr, "Handling request for %s\n", r.URL.Path)

	switch r.URL.Path {
	case "/certsrv/":
		fmt.Fprintf(w, "All good\n")
	case "/certsrv/certnew.p7b":
		pemBytes, err := ioutil.ReadFile("../hack/testdata/ssl/ca/certs/ca-chain.cert.pem")
		if err != nil {
			fmt.Fprint(os.Stderr, err)
		}

		block, _ := pem.Decode(pemBytes)
		_, err = PKCS7.Parse(block.Bytes)

		if err != nil {
			fmt.Fprintf(os.Stderr, "err: %q", err)
		}

		w.Write(block.Bytes)
	case "/certsrv/certnew.cer":
		pemBytes, err := ioutil.ReadFile("../hack/testdata/ssl/ca/intermediate/certs/test.evops.eu.cert.pem")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not find test cert\n")
		}

		certBytes, _ := pem.Decode(pemBytes)

		cert, err := x509.ParseCertificate(certBytes.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not parse test cert\n")
		}

		w.Write(cert.Raw)
	case "/certsrv/certfnsh.asp":
		fmt.Fprintf(w, "certnew.cer?ReqID=12345")
	}
}

var _ = Describe("Controllers/Adcasigningrequest", func() {

	It("should submit request to the CA", func() {
		signingRequest := &adcav1.ADCASigningRequest{}
		signingRequest.Name = "test1"
		signingRequest.Namespace = "default"
		signingRequest.Spec.Domain = "test.adca"
		signingRequest.Spec.SanNames = []string{"test1", "test2", "test3"}

		if err := k8sClient.Create(context.TODO(), signingRequest); err != nil {
			Fail(fmt.Sprintf("Could not create signging request: %q", err))
		}

		os.Setenv("WATCH_NAMESPACE", "default")
		reconciler := &ADCASigningRequestReconciler{
			Client: k8sClient,
			Log:    logf.Log,
		}
		request := ctrl.Request{}
		request.Name = signingRequest.Name
		request.Namespace = signingRequest.Namespace

		result, err := reconciler.Reconcile(request)

		Expect(err).ShouldNot(HaveOccurred())
		Expect(result.Requeue).To(BeFalse(), "Request should not be requeued i.e. it should have been successful")

		Expect(testServerHandler.requestURLs).To(HaveLen(4))
		Expect(testServerHandler.requestURLs).To(ContainElements(
			"/certsrv/",
			"/certsrv/certfnsh.asp",
			"/certsrv/certnew.cer?ReqID=12345&Enc=bin",
			"/certsrv/certnew.p7b?ReqID=CACert&Renewal=0&Enc=bin",
		))

		csrRequest := testServerHandler.requests["/certsrv/certfnsh.asp"]
		csrRequest.request.ParseForm()

		pemRequestString := csrRequest.request.Form["CertRequest"][0]

		Expect(pemRequestString).To(ContainSubstring("BEGIN CERTIFICATE REQUEST"))
		block, _ := pem.Decode([]byte(pemRequestString))
		certRequest, err := x509.ParseCertificateRequest(block.Bytes)

		Expect(err).ShouldNot(HaveOccurred())

		Expect(certRequest.Subject.CommonName).Should(Equal("test.adca"))
		Expect(certRequest.DNSNames).Should(ContainElements("one.local", "two.local"))
	})
})

var _ = BeforeSuite(func(done Done) {
	testServerHandler = &TestServerHandler{
		requests: make(map[string]*TestRequest),
	}
	testServer = httptest.NewServer(testServerHandler)
	fmt.Fprintf(os.Stderr, "Test server running on %s\n", testServer.URL)

	logf.SetLogger(zap.LoggerTo(GinkgoWriter, true))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		AttachControlPlaneOutput: true,
		CRDDirectoryPaths:        []string{filepath.Join("..", "config", "crd", "bases")},
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	err = adcav1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	setupK8sEnvironment(k8sClient, testServer.URL)

	close(done)
}, 60)

func setupK8sEnvironment(c client.Client, url string) {
	configMap := &corev1.ConfigMap{}
	configMap.Name = "adca-config"
	configMap.Namespace = "default"
	configMap.Data = map[string]string{
		"server":                   testServer.URL,
		"adcaCredentialSecretName": "adca-credentials",
	}
	if err := c.Create(context.TODO(), configMap); err != nil {
		fmt.Fprintf(os.Stderr, "Could not create configMap: %q\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Successfully created configMap object\n")
	}

	credentialsSecret := &corev1.Secret{}
	credentialsSecret.Name = "adca-credentials"
	credentialsSecret.Namespace = "default"
	credentialsSecret.StringData = map[string]string{
		"username": "testing",
		"password": "testing",
	}
	c.Create(context.TODO(), credentialsSecret)
}

var _ = AfterSuite(func() {
	By("tearing down the test environment")

	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})
