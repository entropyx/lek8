package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns"
	"github.com/go-acme/lego/v3/registration"
)

type Metadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type Secret struct {
	Kind       string            `json:"kind"`
	APIVersion string            `json:"apiVersion"`
	Metadata   *Metadata         `json:"metadata"`
	Data       map[string]string `json:"data"`
	Type       string            `json:"type"`
}

func (s *Secret) obtain() error {
	config := lego.NewConfig(NewUser(email))
	if test {
		config.CADirURL = lego.LEDirectoryStaging
	}
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}
	provider, err := dns.NewDNSChallengeProviderByName(provider)
	if err != nil {
		return err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return err
	}
	if _, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		return err
	}
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	if err := verifyCert(certificates.IssuerCertificate, certificates.Certificate); err != nil {
		return err
	}
	b64crt := base64.StdEncoding.EncodeToString(certificates.Certificate)
	b64key := base64.StdEncoding.EncodeToString(certificates.PrivateKey)
	s.Data = map[string]string{
		"tls.crt": b64crt,
		"tls.key": b64key,
	}
	return nil
}

func (s *Secret) update() error {
	return s.newRequest("PATCH")
}

func (s *Secret) get() error {
	return s.newRequest("GET")
}

func (s *Secret) newRequest(method string) error {
	var reader io.Reader
	if method == "POST" || method == "PATCH" {
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("https://%s/api/v1/namespaces/%s/secrets/%s", host, namespace, secret), reader)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Accept", "application/json, */*")
	req.Header.Add("Content-Type", "application/strategic-merge-patch+json")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{
				tls.Certificate{
					Certificate: [][]byte{
						cert,
					},
				},
			},
			RootCAs: certPool,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		fmt.Println(string(b))
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	err = json.Unmarshal(b, s)
	return err
}
