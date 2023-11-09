package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var output = flag.String("output", "pools.json", "")

var (
	client *http.Client = &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			DisableCompression:  true,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxConnsPerHost:     100,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: time.Second * 10,
	}
	source = map[string][]string{
		"txt": {
			"https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/crypto_mining.txt",
		},
		"sigma": {
			"https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml",
			"https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/network_connection/net_connection_win_crypto_mining.yml",
			"https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/network/zeek/zeek_dns_mining_pools.yml",
		},
	}
)

func main() {
	flag.Parse()
	fmt.Println("miningpoolfinder generate pools")
	finder := NewFinder()
	if err := finder.Run(); err != nil {
		log.Fatal(err)
	}
	total, err := finder.OutputJSON(*output)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("mining pool address total '%d' \n", total)
}

type Finder struct {
	values map[string]struct{}
}

func NewFinder() *Finder {
	return &Finder{
		values: make(map[string]struct{}),
	}
}

func (f *Finder) Run() error {
	for k, v := range source {
		for _, vv := range v {
			fmt.Printf("request '%s'...\n", vv)
			data, err := f.request(vv)
			if err != nil {
				fmt.Printf("request '%s' error: %s", vv, err.Error())
				continue
			}
			if k == "txt" {
				err = f.findFromTxt(data)
			} else if k == "sigma" {
				err = f.findFromSigma(data)
			}
			if err != nil {
				fmt.Printf("find '%s' type '%s' error: %s", vv, k, err.Error())
			}
		}
	}
	return f.findFromMPS()
}

func (f *Finder) OutputJSON(filename string) (int, error) {
	total := len(f.values)
	if total <= 0 {
		return 0, nil
	}

	pools := make([]string, 0, total)
	for addr := range f.values {
		pools = append(pools, addr)
	}

	data, err := json.Marshal(pools)
	if err != nil {
		return 0, err
	}
	of, err := os.Create(filename)
	if err != nil {
		return 0, err
	}
	defer of.Close()
	_, err = of.Write(data)

	return total, err
}

func (f *Finder) request(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (f *Finder) findFromTxt(content []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		f.values[line] = struct{}{}
	}
	return nil
}

type SigmaHQRule struct {
	Detection struct {
		Selection struct {
			DestinationHostname []string `yaml:"DestinationHostname"`
			QueryContains       []string `yaml:"query|contains"`
			QueryEndswith       []string `yaml:"query|endswith"`
		} `yaml:"selection"`
	} `yaml:"detection"`
}

func (f *Finder) findFromSigma(data []byte) error {
	v := SigmaHQRule{}
	err := yaml.Unmarshal([]byte(data), &v)
	if err != nil {
		return err
	}
	for _, d := range v.Detection.Selection.DestinationHostname {
		f.values[d] = struct{}{}
	}
	for _, d := range v.Detection.Selection.QueryContains {
		f.values[d] = struct{}{}
	}
	for _, d := range v.Detection.Selection.QueryEndswith {
		f.values[d] = struct{}{}
	}
	return nil
}

func (f *Finder) findFromMPS() error {
	fmt.Println("Crawl https://miningpoolstats.stream ...")
	m := NewMpsSiper()
	ts, err := m.ts()
	if err != nil {
		return err
	}
	allcoins, err := m.AllCoins(ts)
	if err != nil {
		return err
	}
	fmt.Printf("Crawl %d  coins \n", len(allcoins))
	for i, coin := range allcoins {
		if i%30 == 0 {
			if ts, err = m.ts(); err != nil {
				continue
			}
		}
		pools, err := m.CoinPools(coin, ts)
		if err != nil {
			fmt.Printf("Crawl '%s' pools error:%s\n", coin, err.Error())
			continue
		}
		fmt.Printf("Crawl '%s' '%d' pools \n", coin, len(pools))
		for _, pool := range pools {
			u, err := url.Parse(pool)
			if err != nil {
				continue
			}
			f.values[u.Host] = struct{}{}
		}
	}
	return nil
}

// sipder
// https://miningpoolstats.stream/
type MpsSiper struct{}

func NewMpsSiper() *MpsSiper {
	return &MpsSiper{}
}

var _timestamp = "https://data.miningpoolstats.stream/data/time?t=%d"

func (m *MpsSiper) ts() (int, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(_timestamp, time.Now().Unix()), nil)
	if err != nil {
		return 0, err
	}
	m.setHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(data))
}

var _allcoins = "https://data.miningpoolstats.stream/data/coins_data.js?t=%d"

type MpsCoinsData struct {
	Data []struct {
		Name string `json:"name"`
		Page string `json:"page"`
	} `json:"data"`
}

func (m *MpsSiper) AllCoins(ts int) ([]string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(_allcoins, ts), nil)
	if err != nil {
		return nil, err
	}

	m.setHeader(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	v := &MpsCoinsData{}
	if err = json.Unmarshal(data, v); err != nil {
		return nil, err
	}

	res := make([]string, 0, len(v.Data))
	for i := range v.Data {
		res = append(res, v.Data[i].Page)
	}
	return res, nil
}

var _coinsPools = "https://data.miningpoolstats.stream/data/%s.js?t=%d"

type MpsCoinPoolsData struct {
	Data []struct {
		Url string `json:"url"`
	} `json:"data"`
}

func (m *MpsSiper) CoinPools(coin string, ts int) ([]string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(_coinsPools, coin, ts), nil)
	if err != nil {
		return nil, err
	}

	m.setHeader(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	v := &MpsCoinPoolsData{}
	if err = json.Unmarshal(data, v); err != nil {
		return nil, err
	}

	res := make([]string, 0, len(v.Data))
	for i := range v.Data {
		res = append(res, v.Data[i].Url)
	}
	return res, nil
}

func (m *MpsSiper) setHeader(req *http.Request) {
	req.Header.Set("authority", "data.miningpoolstats.stream")
	req.Header.Set("accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36")
	req.Header.Set("sec-gpc", "1")
	req.Header.Set("origin", "https://miningpoolstats.stream")
	req.Header.Set("sec-fetch-site", "same-site")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("referer", "https://miningpoolstats.stream/")
	req.Header.Set("accept-language", "en,en-US;q=0.9")
}
