package rbacutils

import (
	"encoding/json"
	"strconv"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

// =========================== convert rbac objects to IMetadata ============================

const (
	ArmoRBACGroup       = "armo.rbac.com"
	relatedObjectsField = "relatedObjects"
)

// DEPRECATED
func RbacObjectIMetadataWrapper(rbacObj *RBAC) (map[string]interface{}, error) {
	m, err := convertToMap(rbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "RBAC"
	m["kind"] = "RBAC"
	m["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	m[relatedObjectsField] = rbacObj.Subjects
	return m, nil
}

// DEPRECATED
func RbacTableObjectIMetadataWrapper(rbacTObj *[]RbacTable) (map[string]interface{}, error) {
	rbacTableMap := map[string]interface{}{}
	r := *rbacTObj
	for i := range r {
		rbacTableMap[strconv.Itoa(i)] = r[i]
	}
	rbacTableMap["name"] = "RbacTable"
	rbacTableMap["kind"] = "RbacTable"
	rbacTableMap["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	rbacTableMap[relatedObjectsField] = []workloadinterface.IMetadata{}
	return rbacTableMap, nil
}

//TODO- DEPRECATE sa2WLIDmap
func SA2WLIDmapIMetadataWrapper(RbacObj map[string][]string) (map[string]interface{}, error) {
	m, err := convertToMap(RbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "SA2WLIDmap"
	m["kind"] = "SA2WLIDmap"
	m["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	m[relatedObjectsField] = []workloadinterface.IMetadata{}
	return m, nil
}

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
