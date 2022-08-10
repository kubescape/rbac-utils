package rbachandler

import (
	"github.com/kubescape/rbac-utils/rbacreporter"
	"github.com/kubescape/rbac-utils/rbacscanner"
)

func HandleRBAC(rScanner rbacscanner.IRbacScanner, rReporter rbacreporter.IRbacReporter) error {
	rbacObjects, err := rScanner.ListResources()
	if err != nil {
		return err
	}
	err = rReporter.ReportRbac(rbacObjects)
	if err != nil {
		return err
	}
	return nil
}
