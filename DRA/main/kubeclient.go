package main

import (
	"fmt"
	"os"

	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type ClientSets struct{ Core coreclientset.Interface }

func NewClientSets() (ClientSets, error) {
	// Try in-cluster first, then KUBECONFIG
	var cfg *rest.Config
	var err error
	if cfg, err = rest.InClusterConfig(); err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			return ClientSets{}, fmt.Errorf("no in-cluster and KUBECONFIG unset")
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return ClientSets{}, fmt.Errorf("build config: %v", err)
		}
	}
	core, err := coreclientset.NewForConfig(cfg)
	if err != nil {
		return ClientSets{}, fmt.Errorf("core client: %v", err)
	}
	return ClientSets{Core: core}, nil
}
