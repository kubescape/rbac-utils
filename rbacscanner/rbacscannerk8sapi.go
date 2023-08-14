package rbacscanner

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	rbacutils "github.com/kubescape/rbac-utils/rbacutils"
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
	saID2WLIDmap, err := rbacutils.InitSAID2WLIDmap(rbacScannerFromK8sAPI.K8s, rbacScannerFromK8sAPI.ClusterName)
	if err != nil {
		return nil, err
	}
	rbacObjects.SAID2WLIDmap = saID2WLIDmap
	return &rbacObjects, nil
}
