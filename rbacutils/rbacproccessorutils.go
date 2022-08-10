package rbacutils

import (
	"encoding/json"
	"strconv"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
)

// =========================== convert rbac objects to IMetadata ============================

const ArmoRBACGroup = "armo.rbac.com"

// DEPRECATED
func RbacObjectIMetadataWrapper(rbacObj *RBAC) (workloadinterface.IMetadata, error) {
	m, err := convertToMap(rbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "RBAC"
	m["kind"] = "RBAC"
	m["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	m[objectsenvelopes.RelatedObjectsKey] = rbacObj.Subjects
	wrappedRbac := objectsenvelopes.NewObject(m)
	return wrappedRbac, nil
}

// DEPRECATED
func RbacTableObjectIMetadataWrapper(rbacTObj *[]RbacTable) (workloadinterface.IMetadata, error) {
	rbacTableMap := map[string]interface{}{}
	r := *rbacTObj
	for i := range r {
		rbacTableMap[strconv.Itoa(i)] = r[i]
	}
	rbacTableMap["name"] = "RbacTable"
	rbacTableMap["kind"] = "RbacTable"
	rbacTableMap["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	rbacTableMap[objectsenvelopes.RelatedObjectsKey] = []workloadinterface.IMetadata{}
	wrappedRbacT := objectsenvelopes.NewObject(rbacTableMap)
	return wrappedRbacT, nil
}

//TODO- DEPRECATE sa2WLIDmap
func SA2WLIDmapIMetadataWrapper(RbacObj map[string][]string) (workloadinterface.IMetadata, error) {
	m, err := convertToMap(RbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "SA2WLIDmap"
	m["kind"] = "SA2WLIDmap"
	m["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	m[objectsenvelopes.RelatedObjectsKey] = []workloadinterface.IMetadata{}
	wrappedSA2WLIDmap := objectsenvelopes.NewObject(m)
	return wrappedSA2WLIDmap, nil
}

func SAID2WLIDmapIMetadataWrapper(RbacObj map[string][]string) (workloadinterface.IMetadata, error) {
	m, err := convertToMap(RbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "SAID2WLIDmap"
	m["kind"] = "SAID2WLIDmap"
	m["apiVersion"] = k8sinterface.JoinGroupVersion(ArmoRBACGroup, "v0beta1")

	m[objectsenvelopes.RelatedObjectsKey] = []workloadinterface.IMetadata{}
	wrappedSAID2WLIDmap := objectsenvelopes.NewObject(m)
	return wrappedSAID2WLIDmap, nil
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
