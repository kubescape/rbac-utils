package rbacutils

import (
	"encoding/json"
	"strconv"

	"github.com/armosec/k8s-interface/workloadinterface"
)

// =========================== convert rbac objects to IMetadata ============================

func RbacObjectIMetadataWrapper(rbacObj *RBAC) (workloadinterface.IMetadata, error) {
	m, err := convertToMap(rbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "RBAC"
	m["kind"] = "RBAC"
	m[workloadinterface.RelatedObjectsKey] = rbacObj.Subjects
	wrappedRbac := workloadinterface.NewObject(m)
	return wrappedRbac, nil
}

func RbacTableObjectIMetadataWrapper(rbacTObj *[]RbacTable) (workloadinterface.IMetadata, error) {
	RbacTableMap := map[string]interface{}{}
	r := *rbacTObj
	for i := range r {
		RbacTableMap[strconv.Itoa(i)] = r[i]
	}
	RbacTableMap["name"] = "RbacTable"
	RbacTableMap["kind"] = "RbacTable"
	RbacTableMap[workloadinterface.RelatedObjectsKey] = []workloadinterface.IMetadata{}
	wrappedRbacT := workloadinterface.NewObject(RbacTableMap)
	return wrappedRbacT, nil
}

func SA2WLIDmapIMetadataWrapper(RbacObj map[string][]string) (workloadinterface.IMetadata, error) {
	m, err := convertToMap(RbacObj)
	if err != nil {
		return nil, err
	}
	m["name"] = "SA2WLIDmap"
	m["kind"] = "SA2WLIDmap"
	m[workloadinterface.RelatedObjectsKey] = []workloadinterface.IMetadata{}
	wrappedSA2WLIDmap := workloadinterface.NewObject(m)
	return wrappedSA2WLIDmap, nil
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
