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

type Manifest struct {
	SHA    string
	Size   int
	Layers []Layer `json:"layers"`
}

type Layer struct {
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
	Digest    string `json:"digest"`
}

func doRequest(method, url string, tokenProvider TokenProvider, repositories ...string) (*http.Response, error) {
	accessToken, err := tokenProvider(repositories...)
	if err != nil {
		return nil, err
	}
	httpClient := http.Client{}
	getRequest, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	getRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	getRequest.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json")
	resp, err := httpClient.Do(getRequest)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad response code: %d", resp.StatusCode)
	}
	return resp, nil
}

func doRequestWithBody(method, url string, tokenProvider TokenProvider, repositories ...string) (*http.Response, []byte, error) {
	resp, err := doRequest(method, url, tokenProvider, repositories...)
	listBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return resp, listBody, nil
}

func getTagList(repository string, tokenProvider TokenProvider) (*DistributionRepository, error) {
	_, body, err := doRequestWithBody(http.MethodGet, fmt.Sprintf("%s/v2/%s/tags/list", *RegistryHost, repository), tokenProvider, repository)
	if err != nil {
		return nil, err
	}
	repo := &DistributionRepository{}
	err = json.Unmarshal(body, repo)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	repo.Name = repository
	return repo, nil
}

func getCatalog(tokenProvider TokenProvider) (*Catalog, error) {
	_, body, err := doRequestWithBody(http.MethodGet, fmt.Sprintf("%s/v2/_catalog", *RegistryHost), tokenProvider)
	if err != nil {
		return nil, errors.New("unable to perform request")
	}
	catalog := &Catalog{}
	err = json.Unmarshal(body, catalog)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	return catalog, nil
}

func getRepositoryManifest(name, tag string, tokenProvider TokenProvider) (*Manifest, error) {
	resp, body, err := doRequestWithBody(http.MethodGet, fmt.Sprintf("%s/v2/%s/manifests/%s", *RegistryHost, name, tag), tokenProvider, name)
	if err != nil {
		return nil, err
	}
	sha := resp.Header.Get("Docker-Content-Digest")
	if len(sha) == 0 {
		return nil, fmt.Errorf("no content digest specified")
	}
	manifest := &Manifest{}
	err = json.Unmarshal(body, manifest)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	manifest.SHA = sha
	for index := range manifest.Layers {
		manifest.Size += manifest.Layers[index].Size
	}
	return manifest, nil
}
