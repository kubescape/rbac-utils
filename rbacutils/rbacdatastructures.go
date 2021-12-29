package rbacutils

import (
	"encoding/json"

	rbac "k8s.io/api/rbac/v1"
)

type RbacObjects struct {
	ClusterRoles        *rbac.ClusterRoleList
	Roles               *rbac.RoleList
	ClusterRoleBindings *rbac.ClusterRoleBindingList
	RoleBindings        *rbac.RoleBindingList
	Rbac                *RBAC        // DEPRECATED
	RbacT               *[]RbacTable // DEPRECATED
	SA2WLIDmap          map[string][]string
}

func (rbacObj RbacObjects) MarshalJSON() ([]byte, error) {
	j, err := json.Marshal(struct {
		ClusterRoles        *rbac.ClusterRoleList        `json:",inline"`
		Roles               *rbac.RoleList               `json:",inline"`
		ClusterRoleBindings *rbac.ClusterRoleBindingList `json:",inline"`
		RoleBindings        *rbac.RoleBindingList        `json:",inline"`
		Rbac                *RBAC                        `json:",inline"`
		RbacT               *[]RbacTable                 `json:",inline"`
	}{
		ClusterRoles:        rbacObj.ClusterRoles,
		Roles:               rbacObj.Roles,
		ClusterRoleBindings: rbacObj.ClusterRoleBindings,
		RoleBindings:        rbacObj.RoleBindings,
		Rbac:                rbacObj.Rbac,
		RbacT:               rbacObj.RbacT,
	})
	if err != nil {
		return nil, err
	}
	return j, nil
}

//Rule -
type Rule struct {
	Rule     rbac.PolicyRule
	LastUsed string
}

//Role -
type Role struct {
	Name  string
	Rules []Rule
}

//Subject - user/group/
type Subject struct {
	rbac.Subject
	Roles []Role
}

// DEPRECATED
//RBAC -
type RBAC struct {
	Kind          string
	Cluster       string
	GeneratedDate string
	GeneratedTime string
	Subjects      []Subject
}

// DEPRECATED
//RbacTable -
type RbacTable struct {
	Cluster   string
	Namespace string
	UserType  string
	Username  string
	Role      string
	Verb      []string
	Resource  []string
}
