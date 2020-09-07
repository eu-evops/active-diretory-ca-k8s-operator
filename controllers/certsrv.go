package controllers

import (
	"fmt"
	"log"
	"net/http"
)

type Certsrv struct {
	Server   string
	Username string
	Password string
}

// ValidateCredentials validates username/password against certsrv endpoint
func (c *Certsrv) ValidateCredentials() error {
	print("Validating credentials for " + c.Server)

	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://"+c.Server+"/certsrv/", nil)
	req.SetBasicAuth("username", "password")

	resp, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
		return err
	}

	if resp.StatusCode > 299 {
		return fmt.Errorf("Failed to reach to axaxl.com: %d", resp.StatusCode)
	}

	log.Println(req.Header)
	log.Println(resp)

	return nil
}
