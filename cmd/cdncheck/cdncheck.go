package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"gopkg.in/yaml.v3"
)

var (
	input  = flag.String("input", "provider.yaml", "")
	output = flag.String("output", "rules.json", "")
)

func main() {
	flag.Parse()
	fmt.Println("cdncheck generate rules")

	if err := generate(*input, *output); err != nil {
		log.Fatal(err)
	}
}

type Provider struct {
	CDN    ProviderItem `yaml:"cdn"`
	WAF    ProviderItem `yaml:"waf"`
	Cloud  ProviderItem `yaml:"cloud"`
	Common struct {
		FQDN map[string][]string `yaml:"fqdn"`
	} `yaml:"common"`
}

type ProviderItem struct {
	ASN  map[string][]string `yaml:"asn"`
	URLS map[string][]string `yaml:"urls"`
}

type Rule struct {
	CDN   map[string][]string `json:"cdn"`
	WAF   map[string][]string `json:"waf"`
	Cloud map[string][]string `json:"cloud"`
	FQDN  map[string][]string `json:"fqdn"`
}

func generate(input, output string) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}

	p := new(Provider)
	if err := yaml.Unmarshal(data, &p); err != nil {
		return err
	}

	rule := Rule{
		CDN:   make(map[string][]string),
		WAF:   make(map[string][]string),
		Cloud: make(map[string][]string),
		FQDN:  p.Common.FQDN,
	}

	fetchInputItem(p.CDN.ASN, p.CDN.URLS, rule.CDN)
	fetchInputItem(p.WAF.ASN, p.WAF.URLS, rule.WAF)
	fetchInputItem(p.Cloud.ASN, p.Cloud.URLS, rule.Cloud)

	// output
	data, err = json.Marshal(rule)
	if err != nil {
		return err
	}
	of, err := os.Create(output)
	if err != nil {
		return err
	}
	defer of.Close()
	_, err = of.Write(data)
	return err
}

func fetchInputItem(asn, urls, data map[string][]string) {
	fmt.Printf("fetchInputItem asn:%s, urls: %s, data: %s\n", asn, urls, data)
	for provider, asn := range asn {
		for _, item := range asn {
			cidrs, err := fetchASNPrefixs(item)
			if err == nil && len(cidrs) > 0 {
				appendData(data, provider, cidrs)
			}

		}
	}

	for provider, urls := range urls {
		for _, url := range urls {
			cidrs, err := getCIDRFromURL(url)
			if err == nil && len(cidrs) > 0 {
				appendData(data, provider, cidrs)
			}
		}
	}
}

func appendData(data map[string][]string, k string, item []string) {
	v, ok := data[k]
	if ok {
		data[k] = append(v, item...)
	} else {
		data[k] = item
	}
}

const (
	asnPrefixUrl = "https://bgp.he.net/%s#_prefixes"
)

func fetchASNPrefixs(asn string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(asnPrefixUrl, asn), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cidrs := cidrRegex.FindAllString(string(data), -1)
	return cidrs, nil
}

var cidrRegex = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,3}`)

// getCIDRFromURL scrapes CIDR ranges for a URL using a regex
func getCIDRFromURL(URL string) ([]string, error) {
	retried := false
retry:
	req, err := http.NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// if the body type is HTML, retry with the first json link in the page (special case for Azure download page to find changing URLs)
	if resp.Header.Get("Content-Type") == "text/html" && !retried {
		var extractedURL string
		docReader, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		docReader.Find("a").Each(func(i int, item *goquery.Selection) {
			src, ok := item.Attr("href")
			if ok && strings.Contains(src, "ServiceTags_Public_") && extractedURL == "" {
				extractedURL = src
			}
		})
		URL = extractedURL
		retried = true
		goto retry
	}

	cidrs := cidrRegex.FindAllString(string(data), -1)
	return cidrs, nil
}
