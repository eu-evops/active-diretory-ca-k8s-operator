package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	PKCS7 "go.mozilla.org/pkcs7"
)

// Certsrv interacts with AD CA web encrollment service
type Certsrv struct {
	Server   string
	Username string
	Password string
}

// ValidateCredentials validates username/password against certsrv endpoint
func (c *Certsrv) ValidateCredentials() error {
	log.Println("Validating credentials for " + c.Server)

	client := &http.Client{}

	req, err := http.NewRequest("GET", c.Server+"/certsrv/", nil)
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
		return err
	}

	if resp.StatusCode > 299 {
		return fmt.Errorf("Failed to reach %s: Response code: %d", c.Server, resp.StatusCode)
	}

	return nil
}

// Retrieve downloads x509 certificate from AD CA based on requestID
func (c *Certsrv) Retrieve(requestID int) (*x509.Certificate, error) {
	log.Println(fmt.Sprintf("Retrieving certificate with request id: %d", requestID))

	client := &http.Client{}
	url := fmt.Sprintf("%s/certsrv/certnew.cer?ReqID=%d&Enc=%s", c.Server, requestID, "bin")
	request, _ := http.NewRequest("GET", url, nil)

	request.Header = map[string][]string{
		"User-Agent": {"Mozilla 5.0 Go Client"},
	}
	request.SetBasicAuth(c.Username, c.Password)

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// RetrieveCACerts downloads CA certificates from AD CA
func (c *Certsrv) RetrieveCACerts() []*x509.Certificate {
	caCertURL := fmt.Sprintf("%s/certsrv/certnew.p7b?ReqID=CACert&Renewal=0&Enc=bin", c.Server)

	log.Printf("Requesting CA certificates from %s", caCertURL)

	request, _ := http.NewRequest("GET", caCertURL, nil)
	request.SetBasicAuth(c.Username, c.Password)
	client := http.Client{}

	response, _ := client.Do(request)
	certBytes, _ := ioutil.ReadAll(response.Body)

	bag, _ := PKCS7.Parse(certBytes)

	return bag.Certificates
}

// Submit requests certificate from AD CA
func (c *Certsrv) Submit(domain string) (*rsa.PrivateKey, int) {
	log.Println(fmt.Sprintf("Submitting certificate request for domain: %s", domain))

	client := &http.Client{}
	requestURL := fmt.Sprintf("%s/certsrv/certfnsh.asp", c.Server)

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 4096)
	subj := pkix.Name{
		CommonName:         domain,
		Country:            []string{"GB"},
		Province:           []string{"Greater London"},
		Locality:           []string{"London"},
		Organization:       []string{"Evops Limited"},
		OrganizationalUnit: []string{"IT"},
	}

	rawSubj := subj.ToRDNSequence()
	ans1Subj, _ := asn1.Marshal(rawSubj)
	signingRequestTemplate := x509.CertificateRequest{
		RawSubject:         ans1Subj,
		SignatureAlgorithm: x509.SHA512WithRSA,

		DNSNames: []string{"one.local", "two.local"},
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &signingRequestTemplate, keyBytes)
	csrPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	form := url.Values{}
	form.Add("Mode", "newreq")
	form.Add("CertRequest", string(csrPemBytes))
	form.Add("CertAttrib", "CertificateTemplate:XLCServer-Build-Pipeline\nUserAgent:PowershellScript")
	form.Add("FriendlyType", "Saved-Request Certificate")
	form.Add("TargetStoreFlags", "0")
	form.Add("SaveCert", "yes")

	request, _ := http.NewRequest("POST", requestURL, strings.NewReader(form.Encode()))

	request.Header = map[string][]string{
		"User-Agent":   {"Mozilla 5.0 Go Client"},
		"Content-Type": {"application/x-www-form-urlencoded"},
	}

	request.SetBasicAuth(c.Username, c.Password)

	response, _ := client.Do(request)
	body, _ := ioutil.ReadAll(response.Body)

	responseBody := string(body)
	matcher := regexp.MustCompile("certnew.cer\\?ReqID=(\\d+)")

	matches := matcher.FindStringSubmatch(responseBody)

	requestID, _ := strconv.Atoi(matches[1])
	return keyBytes, requestID
}
