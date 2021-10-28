package rbacscanner

import (
	"testing"
)

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
