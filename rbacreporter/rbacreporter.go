package rbacreporter

import rbacutils "github.com/kubescape/rbac-utils/rbacutils"

type IRbacReporter interface {
	ReportRbac(rbacObj *rbacutils.RbacObjects) error
	GetClusterName() string
	GetCustomerGUID() string
	SetClusterName(clusterName string)
	SetCustomerGUID(customerGUID string)
}
