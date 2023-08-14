package rbacutils

import (
	"encoding/json"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

// =========================== convert rbac objects to IMetadata ============================

const (
	ArmoRBACGroup       = "armo.rbac.com"
	relatedObjectsField = "relatedObjects"
)

func SAID2WLIDmapIMetadataWrapper(RbacObj map[string][]string) (map[string]interface{}, error) {
	m, err := convertToMap(RbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "SAID2WLIDmap"
	m["kind"] = "SAID2WLIDmap"
	m["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	m[relatedObjectsField] = []workloadinterface.IMetadata{}
	return m, nil
}

func convertToMap(obj interface{}) (map[string]interface{}, error) {
	var inInterface map[string]interface{}
	inrec, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(inrec, &inInterface)
	if err != nil {
		return nil, err
	}
	return inInterface, nil
}
