package rbacutils

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mockWorkload(apiVersion, kind, namespace, name, ownerReferenceKind string) workloadinterface.IWorkload {
	mock := workloadinterface.NewWorkloadMock(nil)
	mock.SetKind(kind)
	mock.SetApiVersion(apiVersion)
	mock.SetName(name)
	mock.SetNamespace(namespace)

	if ownerReferenceKind != "" {
		apiVersion := ""
		switch ownerReferenceKind {
		case "Deployment", "ReplicaSet":
			apiVersion = "apps/v1"
		case "CronJob":
			apiVersion = "batch/v1"
		}
		ownerreferences := []metav1.OwnerReference{
			{
				APIVersion: apiVersion,
				Kind:       ownerReferenceKind,
			},
		}
		workloadinterface.SetInMap(mock.GetWorkload(), []string{"metadata"}, "ownerReferences", ownerreferences)
	}

	return mock
}
