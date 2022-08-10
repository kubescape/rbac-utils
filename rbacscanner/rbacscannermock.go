package rbacscanner

import (
	rbacutils "github.com/kubescape/rbac-utils/rbacutils"
)

type RbacScannerMock struct {
	CustomerGUID string
	ClusterName  string
}

func NewRbacScannerMock(customerGUID string, clusterName string) *RbacScannerMock {
	return &RbacScannerMock{
		CustomerGUID: customerGUID,
		ClusterName:  clusterName}
}

func (rbacScannerMock *RbacScannerMock) GetClusterName() string {
	return rbacScannerMock.ClusterName
}

func (rbacScannerMock *RbacScannerMock) GetCustomerGUID() string {
	return rbacScannerMock.CustomerGUID
}

func (rbacScannerMock *RbacScannerMock) ListResources() (*rbacutils.RbacObjects, error) {
	return nil, nil
}
