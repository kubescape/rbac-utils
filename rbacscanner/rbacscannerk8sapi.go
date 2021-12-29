package rbacscanner

import (
	"github.com/armosec/k8s-interface/k8sinterface"
	rbacutils "github.com/armosec/rbac-utils/rbacutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RbacScannerFromK8sAPI struct {
	K8s *k8sinterface.KubernetesApi
	// clientSet    *kubernetes.Clientset
	CustomerGUID string
	ClusterName  string
}

func NewRbacScannerFromK8sAPI(k8s *k8sinterface.KubernetesApi, customerGUID string, clusterName string) *RbacScannerFromK8sAPI {
	return &RbacScannerFromK8sAPI{
		K8s:          k8s,
		CustomerGUID: customerGUID,
		ClusterName:  clusterName}
}

func (rbacScannerFromK8sAPI *RbacScannerFromK8sAPI) GetClusterName() string {
	return rbacScannerFromK8sAPI.ClusterName
}

func (rbacScannerFromK8sAPI *RbacScannerFromK8sAPI) GetCustomerGUID() string {
	return rbacScannerFromK8sAPI.CustomerGUID
}

// ListResources returns rbac objects and error
func (rbacScannerFromK8sAPI *RbacScannerFromK8sAPI) ListResources() (*rbacutils.RbacObjects, error) {
	// clusterName := rbacScannerFromK8sAPI.GetClusterName()
	rbacObjects := rbacutils.RbacObjects{}
	clusterRoles, err := rbacScannerFromK8sAPI.K8s.KubernetesClient.RbacV1().ClusterRoles().List(rbacScannerFromK8sAPI.K8s.Context, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rbacObjects.ClusterRoles = clusterRoles
	roles, err := rbacScannerFromK8sAPI.K8s.KubernetesClient.RbacV1().Roles("").List(rbacScannerFromK8sAPI.K8s.Context, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rbacObjects.Roles = roles
	clusterRoleBindings, err := rbacScannerFromK8sAPI.K8s.KubernetesClient.RbacV1().ClusterRoleBindings().List(rbacScannerFromK8sAPI.K8s.Context, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rbacObjects.ClusterRoleBindings = clusterRoleBindings
	roleBindings, err := rbacScannerFromK8sAPI.K8s.KubernetesClient.RbacV1().RoleBindings("").List(rbacScannerFromK8sAPI.K8s.Context, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rbacObjects.RoleBindings = roleBindings
	// myRBAC := rbacutils.InitRbac(rbacScannerFromK8sAPI.ClusterName, clusterRoles, roles, clusterRoleBindings, roleBindings)
	// rbacObjects.Rbac = myRBAC
	// rbactable := rbacutils.InitRbacTable(rbacScannerFromK8sAPI.ClusterName, clusterRoles, roles, clusterRoleBindings, roleBindings)
	// rbacObjects.RbacT = rbactable
	sa2WLIDmap, err := rbacutils.InitSA2WLIDmap(rbacScannerFromK8sAPI.K8s, rbacScannerFromK8sAPI.ClusterName)
	if err != nil {
		return nil, err
	}
	rbacObjects.SA2WLIDmap = sa2WLIDmap
	return &rbacObjects, nil
}
