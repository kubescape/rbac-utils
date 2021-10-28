package rbacscanner

import rbacutils "github.com/armosec/rbac-utils/rbacutils"

type IRbacScanner interface {
	ListResources() (*rbacutils.RbacObjects, error)
	GetClusterName() string
	GetCustomerGUID() string
}
