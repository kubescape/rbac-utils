package rbacscanner

import (
	"testing"
	// "github.com/armosec/k8s-interface/k8sinterface"
	// "github.com/armosec/rbac-utils/rbacutils"
)

// func TestListResources(t *testing.T) {
// 	rs := NewRbacScannerFromK8sAPI(k8sinterface.NewKubernetesApi(), "1234", "cluster-example")
// 	rbacobj, err := rs.ListResources()
// 	if err != nil {
// 		t.Errorf("error listing resources: %s", err)
// 	}
// 	if rbacobj.ClusterRoleBindings == nil {
// 		t.Errorf("error getting ClusterRoleBindings")
// 	}
// 	if rbacobj.ClusterRoles == nil {
// 		t.Errorf("error getting ClusterRoles")
// 	}
// 	if rbacobj.RoleBindings == nil {
// 		t.Errorf("error getting RoleBindings")
// 	}
// 	if rbacobj.Roles == nil {
// 		t.Errorf("error getting Roles")
// 	}
// 	if rbacobj.Rbac == nil {
// 		t.Errorf("error creating RBAC struct")
// 	}
// 	if rbacobj.RbacT == nil {
// 		t.Errorf("error creating RBAC Table struct")
// 	}
// 	if rbacobj.SA2WLIDmap == nil {
// 		t.Errorf("error creating SA2WLIDmap")
// 	}
// 	m1, err := rbacutils.RbacObjectIMetadataWrapper(rbacobj.Rbac)
// 	if err != nil {
// 		t.Errorf("error wrapping Rbac")
// 	}
// 	if m1.GetName() != "RBAC" {
// 		t.Errorf("error wrapping Rbac")
// 	}
// 	m2, err := rbacutils.RbacTableObjectIMetadataWrapper(rbacobj.RbacT)
// 	if err != nil {
// 		t.Errorf("error wrapping RbacT")
// 	}
// 	if m2.GetName() != "RbacTable" {
// 		t.Errorf("error wrapping RbacT")
// 	}
// 	m3, err := rbacutils.SA2WLIDmapIMetadataWrapper(rbacobj.SA2WLIDmap)
// 	if err != nil {
// 		t.Errorf("error wrapping SA2WLIDmap")
// 	}
// 	if m3.GetName() != "SA2WLIDmap" {
// 		t.Errorf("error wrapping SA2WLIDmap")
// 	}
// }

func TestGetClusterName(t *testing.T) {
	rs := NewRbacScannerMock("1234", "cluster-example")
	if rs.GetClusterName() != "cluster-example" {
		t.Errorf("error in rbacscanner.GetClusterName")
	}
}

func TestGetCustomerGUID(t *testing.T) {
	rs := NewRbacScannerMock("1234", "cluster-example")
	if rs.GetCustomerGUID() != "1234" {
		t.Errorf("error in rbacscanner.GetClusterName")
	}
}
