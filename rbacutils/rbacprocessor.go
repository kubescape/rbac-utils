package rbacutils

import (
	"fmt"
	"time"

	"github.com/armosec/k8s-interface/k8sinterface"
	rbac "k8s.io/api/rbac/v1"
)

var ResourceGroupMapping = map[string]string{
	"pods":         "/v1",
	"daemonsets":   "apps/v1",
	"deployments":  "apps/v1",
	"replicasets":  "apps/v1",
	"statefulsets": "apps/v1",
	"jobs":         "batch/v1",
	"cronjobs":     "batch/v1beta1",
}

// ============================= SA 2 WLID map ===================================================
// create service account to WLID map

func InitSA2WLIDmap(k8sAPI *k8sinterface.KubernetesApi, clusterName string) (map[string][]string, error) {
	groupVersionResource, err := k8sinterface.GetGroupVersionResource("serviceaccounts")
	if err != nil {
		return nil, err
	}
	serviceaccounts, err := k8sAPI.ListWorkloads(&groupVersionResource, "", nil, nil)
	if err != nil {
		return nil, err
	}
	sa2WLIDmap := make(map[string][]string)
	for saIdx := range serviceaccounts {
		if serviceaccounts[saIdx].GetKind() == "ServiceAccount" {
			sa2WLIDmap[serviceaccounts[saIdx].GetName()] = make([]string, 0)
		}
	}
	allworkloads, err := ListAllWorkloads(k8sAPI)
	if err != nil {
		return sa2WLIDmap, err
	}
	for _, wl := range allworkloads {
		serviceAccountName := wl.GetServiceAccountName()
		if wlidsList, ok := sa2WLIDmap[serviceAccountName]; ok {
			wlidsList = append(wlidsList, wl.GenerateWlid(clusterName))
			sa2WLIDmap[serviceAccountName] = wlidsList
		} else {
			sa2WLIDmap[serviceAccountName] = []string{wl.GenerateWlid(clusterName)}
		}
	}
	return sa2WLIDmap, nil
}

func ListAllWorkloads(k8sAPI *k8sinterface.KubernetesApi) ([]k8sinterface.IWorkload, error) {
	workloads := []k8sinterface.IWorkload{}
	var errs error
	for resource := range ResourceGroupMapping {
		groupVersionResource, err := k8sinterface.GetGroupVersionResource(resource)
		if err != nil {
			errs = fmt.Errorf("%v\n%s", errs, err.Error())
			continue
		}
		w, err := k8sAPI.ListWorkloads(&groupVersionResource, "", nil, nil)
		if err != nil {
			errs = fmt.Errorf("%v\n%s", errs, err.Error())
			continue
		}
		if len(w) == 0 {
			continue
		}
		workloads = append(workloads, w...)
	}
	return workloads, errs
}

// ================================== rbac struct ======================================

// DEPRECATED
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

// DEPRECATED
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
