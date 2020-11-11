/*
Copyright 2020. Huawei Technologies Co., Ltd. All rights reserved.

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

package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/msalihkarakasli/go-hms-push/push/config"
)

type PushRequest struct {
	Method string
	URL    string
	Body   []byte
	Header []HTTPOption
}

type PushResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type HTTPProxyConfig struct {
	ProxyUrl        *url.URL
	ProxyCACertPath string
}

type HTTPRetryConfig struct {
	MaxRetryTimes int
	RetryInterval time.Duration
}

type HTTPClientConfig struct {
	ProxyConfig *HTTPProxyConfig
	RetryConfig *HTTPRetryConfig
}

type HTTPClient struct {
	Client      *http.Client
	RetryConfig *HTTPRetryConfig
}

type HTTPOption func(r *http.Request)

func NewHTTPClientConfig(c *config.Config) (*HTTPClientConfig, error) {
	if c == nil {
		return nil, errors.New("config is nil")
	}

	httpClientConfig := HTTPClientConfig{
		RetryConfig: &HTTPRetryConfig{
			MaxRetryTimes: c.MaxRetryTimes,
			RetryInterval: c.RetryInterval,
		},
	}

	if len(c.HttpProxyUrl) > 0 {
		proxyURL, err := url.ParseRequestURI(c.HttpProxyUrl)
		if err != nil {
			return nil, fmt.Errorf("parse proxy url error: %w", err)
		}
		httpClientConfig.ProxyConfig = &HTTPProxyConfig{ProxyUrl: proxyURL, ProxyCACertPath: c.HttpProxyCACertPath}
	}

	return &httpClientConfig, nil
}

func SetHeader(key string, value string) HTTPOption {
	return func(r *http.Request) {
		r.Header.Set(key, value)
	}
}

func NewHTTPClient(config *HTTPClientConfig) (*HTTPClient, error) {
	var proxyURL *url.URL = nil

	if config != nil {
		if config.ProxyConfig != nil && config.ProxyConfig.ProxyUrl != nil {
			proxyURL = config.ProxyConfig.ProxyUrl
			urlScheme := strings.ToLower(proxyURL.Scheme)
			if urlScheme != "http" && urlScheme != "https" {
				return nil, errors.New("unsupported proxy url scheme")
			}
		}
		if config.RetryConfig != nil {
			if config.RetryConfig.MaxRetryTimes < 1 || config.RetryConfig.MaxRetryTimes > 5 {
				return nil, errors.New("maximum retry times value cannot be less than 1 and more than 5")
			}
		}
	}

	tr := http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{},
	}

	if proxyURL != nil {
		cacertPath := config.ProxyConfig.ProxyCACertPath
		if cacertPath != "" {
			bytes, err := ioutil.ReadFile(cacertPath)
			if err != nil {
				return nil, err
			}

			rootCAs, _ := x509.SystemCertPool()
			if rootCAs == nil {
				rootCAs = x509.NewCertPool()
			}
			if ok := rootCAs.AppendCertsFromPEM(bytes); !ok {
				return nil, errors.New("failed to parse proxy server CA certificate")
			}

			tr.TLSClientConfig.RootCAs = rootCAs
		}

		tr.Proxy = http.ProxyURL(proxyURL)
	}

	httpClient := HTTPClient{Client: &http.Client{Transport: &tr}}
	if config != nil && config.RetryConfig != nil {
		httpClient.RetryConfig = config.RetryConfig
	} else {
		httpClient.RetryConfig = &HTTPRetryConfig{
			MaxRetryTimes: 1,
			RetryInterval: 0,
		}
	}

	return &httpClient, nil
}

func (r *PushRequest) buildHTTPRequest() (*http.Request, error) {
	var body io.Reader

	if r.Body != nil {
		body = bytes.NewBuffer(r.Body)
	}

	req, err := http.NewRequest(r.Method, r.URL, body)
	if err != nil {
		return nil, err
	}

	for _, opt := range r.Header {
		opt(req)
	}

	return req, nil
}

func (c *HTTPClient) doHttpRequest(req *PushRequest) (*PushResponse, error) {
	request, err := req.buildHTTPRequest()
	if err != nil {
		return nil, err
	}

	resp, err := c.Client.Do(request)

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return &PushResponse{
		Status: resp.StatusCode,
		Header: resp.Header,
		Body:   body,
	}, nil
}

func (c *HTTPClient) DoHttpRequest(ctx context.Context, req *PushRequest) (*PushResponse, error) {
	var (
		result *PushResponse
		err    error
	)
	for retryTimes := 0; retryTimes < c.RetryConfig.MaxRetryTimes; retryTimes++ {
		result, err = c.doHttpRequest(req)

		if err == nil {
			break
		}

		if !c.pendingForRetry(ctx) {
			break
		}
	}
	return result, err
}

func (c *HTTPClient) pendingForRetry(ctx context.Context) bool {
	if c.RetryConfig.RetryInterval > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(c.RetryConfig.RetryInterval):
			return true
		}
	}
	return false
}
