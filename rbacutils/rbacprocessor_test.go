package rbacutils

import (
	"testing"

	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestInitRbacTable_RoleBindingToClusterRoleKeepsBindingNamespace(t *testing.T) {
	clusterRoles := &rbac.ClusterRoleList{Items: []rbac.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "view"},
			Rules:      []rbac.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}},
		},
	}}
	roleBindings := &rbac.RoleBindingList{Items: []rbac.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "view-binding", Namespace: "team-a"},
			Subjects:   []rbac.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:    rbac.RoleRef{Name: "view", Kind: "ClusterRole"},
		},
	}}

	rows := InitRbacTable("test-cluster", clusterRoles, &rbac.RoleList{}, &rbac.ClusterRoleBindingList{}, roleBindings)

	if len(*rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(*rows))
	}
	if got := (*rows)[0].Namespace; got != "team-a" {
		t.Errorf("RoleBinding %q grants ClusterRole %q rules only within its own namespace, want Namespace=%q, got %q",
			"view-binding", "view", "team-a", got)
	}
}
