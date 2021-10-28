package rbacutils

import (
	"encoding/json"
	"time"

	rbac "k8s.io/api/rbac/v1"
)

type RbacObjects struct {
	ClusterRoles        *rbac.ClusterRoleList
	Roles               *rbac.RoleList
	ClusterRoleBindings *rbac.ClusterRoleBindingList
	RoleBindings        *rbac.RoleBindingList
	Rbac                *RBAC
	RbacT               *[]RbacTable
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

// ================================== rbac struct ======================================

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

//RBAC -
type RBAC struct {
	Kind          string
	Cluster       string
	GeneratedDate string
	GeneratedTime string
	Subjects      []Subject
}

// InitRbac -
func InitRbac(clusterName string, clusterRoles *rbac.ClusterRoleList, roles *rbac.RoleList, clusterRoleBindings *rbac.ClusterRoleBindingList, roleBindings *rbac.RoleBindingList) *RBAC {
	currentTime := time.Now()
	MyRBAC := RBAC{Kind: "RoleUsageReport", Cluster: clusterName,
		GeneratedDate: currentTime.Format("02.01.2006"), GeneratedTime: currentTime.Format("15:04:05")}
	//add subject->rules from clusterrolebindings
	for _, clusterRoleBinding := range clusterRoleBindings.Items {
		if (clusterRoleBinding.Subjects != nil) && (len(clusterRoleBinding.Subjects) != 0) {
			for _, subject := range clusterRoleBinding.Subjects {
				newRules := []Rule{}
				var foundRole = false
				for _, clusterRole := range clusterRoles.Items {
					if clusterRole.Name == clusterRoleBinding.RoleRef.Name {
						for _, rule := range clusterRole.Rules {
							newRule := Rule{Rule: rule, LastUsed: "change this"}
							newRules = append(newRules, newRule)
						}
						foundRole = true
						break
					}
				}
				if !foundRole {
					for _, role := range roles.Items {
						if role.Name == clusterRoleBinding.RoleRef.Name {
							for _, rule := range role.Rules {
								newRule := Rule{Rule: rule, LastUsed: "change this"}
								newRules = append(newRules, newRule)
							}
							break
						}
					}
				}
				var newRole = Role{Name: clusterRoleBinding.RoleRef.Name, Rules: newRules}
				i, found := ExistsSubject(MyRBAC.Subjects, subject.Name)
				if !found {
					var newSubject = Subject{Subject: subject}
					newSubject.Roles = append(newSubject.Roles, newRole)
					MyRBAC.Subjects = append(MyRBAC.Subjects, newSubject)
				} else {
					MyRBAC.Subjects[i].Roles = append(MyRBAC.Subjects[i].Roles, newRole)
				}
			}
		}
	}
	//add subject->rules from rolebindings
	for _, roleBinding := range roleBindings.Items {
		if (roleBinding.Subjects != nil) && (len(roleBinding.Subjects) != 0) {
			for _, subject := range roleBinding.Subjects {
				newRules := []Rule{}
				var foundRole = false
				for _, role := range roles.Items {
					if role.Name == roleBinding.RoleRef.Name {
						for _, rule := range role.Rules {
							newRule := Rule{Rule: rule, LastUsed: "change this"}
							newRules = append(newRules, newRule)
						}
						foundRole = true
						break
					}
				}
				if !foundRole {
					for _, clusterRole := range clusterRoles.Items {
						if clusterRole.Name == roleBinding.RoleRef.Name {
							for _, rule := range clusterRole.Rules {
								newRule := Rule{Rule: rule, LastUsed: "change this"}
								newRules = append(newRules, newRule)
							}
							break
						}
					}
				}
				var newRole = Role{Name: roleBinding.RoleRef.Name, Rules: newRules}
				i, found := ExistsSubject(MyRBAC.Subjects, subject.Name)
				if !found {
					var newSubject = Subject{Subject: subject}
					newSubject.Roles = append(newSubject.Roles, newRole)
					MyRBAC.Subjects = append(MyRBAC.Subjects, newSubject)
				} else {
					MyRBAC.Subjects[i].Roles = append(MyRBAC.Subjects[i].Roles, newRole)
				}
			}
		}
	}
	return &MyRBAC
}

// ExistsSubject -
func ExistsSubject(list []Subject, subjectName string) (int, bool) {
	for i, sub := range list {
		if sub.Name == subjectName {
			return i, true
		}
	}
	return -1, false
}

//  =========================== rbac table ======================
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

//InitRbacTable -
func InitRbacTable(clustername string, clusterRoles *rbac.ClusterRoleList, roles *rbac.RoleList, clusterRoleBindings *rbac.ClusterRoleBindingList, roleBindings *rbac.RoleBindingList) *[]RbacTable {
	var RbacTableList = []RbacTable{}
	for _, clusterRoleBinding := range clusterRoleBindings.Items {
		if (clusterRoleBinding.Subjects != nil) && (len(clusterRoleBinding.Subjects) != 0) {
			for _, subject := range clusterRoleBinding.Subjects {
				var foundRole = false
				for _, clusterRole := range clusterRoles.Items {
					if clusterRole.Name == clusterRoleBinding.RoleRef.Name {
						for _, rule := range clusterRole.Rules {
							//create new row in table
							var RbacTable = RbacTable{Cluster: clustername, Namespace: "All (*)", UserType: subject.Kind,
								Username: subject.Name, Role: clusterRole.Name, Verb: rule.Verbs, Resource: rule.Resources}
							RbacTableList = append(RbacTableList, RbacTable)
						}
						foundRole = true
						break
					}
				}
				if !foundRole {
					for _, role := range roles.Items {
						if role.Name == clusterRoleBinding.RoleRef.Name {
							for _, rule := range role.Rules {
								//create new row in table
								var RbacTable = RbacTable{Cluster: clustername, Namespace: role.Namespace, UserType: subject.Kind,
									Username: subject.Name, Role: role.Name, Verb: rule.Verbs, Resource: rule.Resources}
								RbacTableList = append(RbacTableList, RbacTable)
							}
							break
						}
					}
				}
			}
		}
	}
	for _, roleBinding := range roleBindings.Items {
		if (roleBinding.Subjects != nil) && (len(roleBinding.Subjects) != 0) {
			for _, subject := range roleBinding.Subjects {
				var foundRole = false
				for _, clusterRole := range clusterRoles.Items {
					if clusterRole.Name == roleBinding.RoleRef.Name {
						for _, rule := range clusterRole.Rules {
							//create new row in table
							var RbacTable = RbacTable{Cluster: clustername, Namespace: "All (*)", UserType: subject.Kind,
								Username: subject.Name, Role: clusterRole.Name, Verb: rule.Verbs, Resource: rule.Resources}
							RbacTableList = append(RbacTableList, RbacTable)
						}
						foundRole = true
						break
					}
				}
				if !foundRole {
					for _, role := range roles.Items {
						if role.Name == roleBinding.RoleRef.Name {
							for _, rule := range role.Rules {
								//create new row in table
								var RbacTable = RbacTable{Cluster: clustername, Namespace: role.Namespace, UserType: subject.Kind,
									Username: subject.Name, Role: role.Name, Verb: rule.Verbs, Resource: rule.Resources}
								RbacTableList = append(RbacTableList, RbacTable)
							}
							break
						}
					}
				}
			}
		}
	}
	return &RbacTableList
}
