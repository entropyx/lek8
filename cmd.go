package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	secretsPath = "/var/run/secrets/kubernetes.io/serviceaccount/"
)

var cert []byte
var certPool *x509.CertPool
var domains []string
var email string
var host string
var namespace string
var provider string
var secret string
var test bool
var token string

var rootCmd = &cobra.Command{
	Use:   "lek8",
	Short: "Automatically manage your Let's Encrypt SSL certificates in Kubernetes",
	Long:  `Automatically manage your Let's Encrypt SSL certificates in Kubernetes`,
	Run: func(cmd *cobra.Command, args []string) {
		defer fmt.Println("Bye!")
		fmt.Println("host:", host)
		fmt.Println("provider:", provider)
		fmt.Println("email:", email)
		fmt.Println("domains:", domains)
		fmt.Println("secret:", secret)

		if err := readSecretsPath(); err != nil {
			panic(err)
		}
		s := &Secret{}
		if err := s.get(); err != nil {
			panic(err)
		}
		b64crt, ok := s.Data["tls.crt"]
		if ok {
			tlscrt, err := base64.StdEncoding.DecodeString(b64crt)
			if err != nil {
				panic(err)
			}
			block, _ := pem.Decode([]byte(tlscrt))
			xcert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(err)
			}
			expiration := xcert.NotAfter
			now := time.Now()
			t := time.Duration(expiration.UnixNano() - now.UnixNano())
			fmt.Printf("%d days before expiration date\n", uint(t.Hours()/24))
			if t > 30*24*time.Hour {
				return
			}
		}
		fmt.Println("Obtaining new certificate")
		if err := s.obtain(); err != nil {
			panic(err)
		}
		fmt.Println("Updating secret")
		if err := s.update(); err != nil {
			panic(err)
		}
	},
}

func Execute() {
	rootCmd.Flags().StringVarP(&email, "email", "e", "", "email address for account notifications")
	rootCmd.Flags().StringVar(&host, "host", "kubernetes", "kubernetes host")
	rootCmd.Flags().StringVarP(&provider, "provider", "p", "", "DNS provider")
	rootCmd.Flags().StringVarP(&secret, "secret", "s", "", "secret name")
	rootCmd.Flags().BoolVarP(&test, "test", "t", false, "obtain a test certificate from a staging server")
	rootCmd.Flags().StringArrayVarP(&domains, "domain", "d", []string{}, "list of domains to obtain a certificate for")

	rootCmd.MarkFlagRequired("domain")
	rootCmd.MarkFlagRequired("email")
	rootCmd.MarkFlagRequired("provider")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func readSecretsPath() error {
	b, err := ioutil.ReadFile(secretsPath + "namespace")
	if err != nil {
		return err
	}
	namespace = replace(string(b))
	fmt.Println("namespace:", namespace)
	b, err = ioutil.ReadFile(secretsPath + "token")
	if err != nil {
		return err
	}
	token = replace(string(b))
	b, err = ioutil.ReadFile(secretsPath + "ca.crt")
	if err != nil {
		return err
	}
	cert = b
	block, _ := pem.Decode(cert)
	if block == nil {
		return fmt.Errorf("invalid API cert")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	certPool = x509.NewCertPool()
	certPool.AddCert(crt)
	return nil
}

func replace(s string) string {
	return strings.Replace(s, "\n", "", 1)
}

func verifyCert(root []byte, cert []byte) error {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(root); !ok {
		return errors.New("unable to append root cert")
	}
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return errors.New("failed to parse certificate PEM")
	}
	xcert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	fmt.Println("issuer", xcert.Issuer)
	fmt.Println("issuing url", xcert.IssuingCertificateURL)
	for _, domain := range domains {
		opts := x509.VerifyOptions{
			DNSName: domain,
			Roots:   pool,
		}
		if _, err = xcert.Verify(opts); err != nil {
			return err
		}
	}
	return nil
}
