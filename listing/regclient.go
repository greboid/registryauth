package listing

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type Catalog struct {
	Repositories []string `json:"repositories"`
}

type DistributionRepository struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

func getTagList(repository string, tokenProvider TokenProvider) (*DistributionRepository, error) {
	accessToken, err := tokenProvider(repository)
	if err != nil {
		return nil, errors.New("error obtaining access token")
	}
	httpClient := http.Client{}
	getRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v2/%s/tags/list", *RegistryHost, repository), nil)
	if err != nil {
		return nil, errors.New("error creating request")
	}
	getRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := httpClient.Do(getRequest)
	if err != nil {
		return nil, errors.New("unable to perform request")
	}
	listBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("unable to read body")
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	repo := &DistributionRepository{}
	err = json.Unmarshal(listBody, repo)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	repo.Name = repository
	return repo, nil
}

func getCatalog(tokenProvider TokenProvider) (*Catalog, error) {
	accessToken, err := tokenProvider()
	if err != nil {
		return nil, errors.New("error obtaining access token")
	}
	httpClient := http.Client{}
	getRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v2/_catalog", *RegistryHost), nil)
	if err != nil {
		return nil, errors.New("error creating request")
	}
	getRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := httpClient.Do(getRequest)
	if err != nil {
		return nil, errors.New("unable to perform request")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad response code: %d", resp.StatusCode)
	}
	listBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("unable to read body")
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	catalog := &Catalog{}
	err = json.Unmarshal(listBody, catalog)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	return catalog, nil
}

func getRepositorySHA(name, tag string, tokenProvider TokenProvider) (string, error) {
	resp, err := getManifest(http.MethodHead, name, tag, tokenProvider)
	if err != nil {
		return "", err
	}
	sha := resp.Header.Get("Docker-Content-Digest")
	if len(sha) == 0 {
		return "", fmt.Errorf("no content digest specified")
	}
	return sha, nil
}

func getManifest(method, name, tag string, tokenProvider TokenProvider) (*http.Response, error) {
	accessToken, err := tokenProvider(name)
	if err != nil {
		return nil, errors.New("error obtaining access token")
	}
	httpClient := http.Client{}
	getRequest, err := http.NewRequest(method, fmt.Sprintf("%s/v2/%s/manifests/%s", *RegistryHost, name, tag), nil)
	if err != nil {
		return nil, errors.New("error creating request")
	}
	getRequest.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json")
	getRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := httpClient.Do(getRequest)
	if err != nil {
		return nil, errors.New("unable to perform request")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad response code: %d", resp.StatusCode)
	}
	return resp, nil
}
