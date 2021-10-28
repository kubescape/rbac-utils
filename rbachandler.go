package rbachandler

import (
	"github.com/armosec/rbac-utils/rbacreporter"
	"github.com/armosec/rbac-utils/rbacscanner"
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
