package rbacutils

import (
	"fmt"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
)

var (
	ResourceGroupMapping = []string{
		"pods",
		"daemonsets",
		"deployments",
		"replicasets",
		"statefulsets",
		"jobs",
		"cronjobs",
	}

	serviceaccountkind    = "ServiceAccount"
	serviceaccountversion = "v1"
)

// ============================= SA 2 WLID map ===================================================

func ListAllWorkloads(k8sAPI *k8sinterface.KubernetesApi) ([]k8sinterface.IWorkload, error) {
	workloads := []k8sinterface.IWorkload{}
	var errs error
	for i := range ResourceGroupMapping {
		groupVersionResource, err := k8sinterface.GetGroupVersionResource(ResourceGroupMapping[i])
		if err != nil {
			errs = fmt.Errorf("%v\n%s", errs, err.Error())
			continue
		}
		w, err := k8sAPI.ListWorkloads(&groupVersionResource, "", nil, nil)
		if err != nil {
			errs = fmt.Errorf("%v\n%s", errs, err.Error())
			continue
		}
		if len(w) == 0 {
			continue
		}
		workloads = append(workloads, w...)
	}
	return workloads, errs
}

func InitSAID2WLIDmap(k8sAPI *k8sinterface.KubernetesApi, clusterName string) (map[string][]string, error) {
	groupVersionResource, err := k8sinterface.GetGroupVersionResource("serviceaccounts")
	if err != nil {
		return nil, err
	}
	serviceaccounts, err := k8sAPI.ListWorkloads(&groupVersionResource, "", nil, nil)
	if err != nil {
		return nil, err
	}
	saID2WLIDmap := make(map[string][]string)
	for saIdx := range serviceaccounts {
		if serviceaccounts[saIdx].GetKind() == "ServiceAccount" {
			saID2WLIDmap[serviceaccounts[saIdx].GetID()] = make([]string, 0)
		}
	}
	allworkloads, err := ListAllWorkloads(k8sAPI)
	if err != nil {
		return saID2WLIDmap, nil
	}
	for _, wl := range allworkloads {
		if !k8sinterface.WorkloadHasParent(wl) {
			connectedSA := wl.GetServiceAccountName()
			if connectedSA == "" {
				connectedSA = "default"
			}
			saID := "/" + strings.Join([]string{serviceaccountversion, wl.GetNamespace(), serviceaccountkind, connectedSA}, "/")
			if wlidsList, ok := saID2WLIDmap[saID]; ok {
				wlidsList = append(wlidsList, wl.GenerateWlid(clusterName))
				saID2WLIDmap[saID] = wlidsList
			} else {
				saID2WLIDmap[saID] = []string{wl.GenerateWlid(clusterName)}
			}
		}
	}
	return saID2WLIDmap, nil
}
