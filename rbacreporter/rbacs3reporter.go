package rbacreporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	rbacutils "github.com/kubescape/rbac-utils/rbacutils"
	rbac "k8s.io/api/rbac/v1"
)

type S3RBACReporter struct {
	customerGUID string
	clusterName  string
	S3Bucket     string
}

func NewS3RBACReporter(customerGUID string, clusterName string, s3Bucket string) *S3RBACReporter {
	return &S3RBACReporter{
		customerGUID: customerGUID,
		clusterName:  clusterName,
		S3Bucket:     s3Bucket}
}

func (s3RBACReporter *S3RBACReporter) GetClusterName() string {
	return s3RBACReporter.clusterName
}

func (s3RBACReporter *S3RBACReporter) GetCustomerGUID() string {
	return s3RBACReporter.customerGUID
}

func (s3RBACReporter *S3RBACReporter) SetClusterName(clusterName string) {
	s3RBACReporter.clusterName = clusterName
}

func (s3RBACReporter *S3RBACReporter) SetCustomerGUID(customerGUID string) {
	s3RBACReporter.customerGUID = customerGUID
}

func (s3RBACReporter *S3RBACReporter) ReportRbac(rbacObj *rbacutils.RbacObjects) error {
	if err := s3RBACReporter.Uploadclusterroles(rbacObj.ClusterRoles, s3RBACReporter.GetCustomerGUID(), s3RBACReporter.GetClusterName()); err != nil {
		return err
	}
	if err := s3RBACReporter.Uploadroles(rbacObj.Roles, s3RBACReporter.GetCustomerGUID(), s3RBACReporter.GetClusterName()); err != nil {
		return err
	}
	if err := s3RBACReporter.UploadclusterRoleBindings(rbacObj.ClusterRoleBindings, s3RBACReporter.GetCustomerGUID(), s3RBACReporter.GetClusterName()); err != nil {
		return err
	}
	if err := s3RBACReporter.UploadroleBindings(rbacObj.RoleBindings, s3RBACReporter.GetCustomerGUID(), s3RBACReporter.GetClusterName()); err != nil {
		return err
	}
	return nil
}

// UploadroleBindings -
func (s3RBACReporter *S3RBACReporter) UploadroleBindings(roleBindings *rbac.RoleBindingList, customer string, cluster string) error {
	key := customer + "/" + cluster + "/" + "roleBindings.json"
	scanDeliveryBucket := s3RBACReporter.S3Bucket
	if len(scanDeliveryBucket) == 0 {
		return fmt.Errorf("must configure S3_BUCKET")
	}
	jsonRaw, _ := json.Marshal(roleBindings)
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return fmt.Errorf("error configuring S3 client (%s)", key)
	}
	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(scanDeliveryBucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(jsonRaw),
	})
	if err != nil {
		return fmt.Errorf("error posting scan results to S3 - error: %s (%s)", err, key)
	} else {
		log.Printf("uploaded %s to bucket %s", key, scanDeliveryBucket)
		return nil
	}
}

// UploadclusterRoleBindings -
func (s3RBACReporter *S3RBACReporter) UploadclusterRoleBindings(clusterRoleBindings *rbac.ClusterRoleBindingList, customer string, cluster string) error {
	key := customer + "/" + cluster + "/" + "clusterRoleBindings.json"
	scanDeliveryBucket := s3RBACReporter.S3Bucket
	if len(scanDeliveryBucket) == 0 {
		return fmt.Errorf("must configure S3_BUCKET")
	}
	jsonRaw, _ := json.Marshal(clusterRoleBindings)
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return fmt.Errorf("error configuring S3 client (%s)", key)
	}
	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(scanDeliveryBucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(jsonRaw),
	})
	if err != nil {
		return fmt.Errorf("error posting scan results to S3 - error: %s (%s)", err, key)
	} else {
		log.Printf("Uploaded %s to bucket %s", key, scanDeliveryBucket)
		return nil
	}
}

// Uploadroles -
func (s3RBACReporter *S3RBACReporter) Uploadroles(roles *rbac.RoleList, customer string, cluster string) error {
	key := customer + "/" + cluster + "/" + "roles.json"
	scanDeliveryBucket := s3RBACReporter.S3Bucket
	if len(scanDeliveryBucket) == 0 {
		return fmt.Errorf("must configure S3_BUCKET")
	}
	jsonRaw, _ := json.Marshal(roles)
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return fmt.Errorf("error configuring S3 client (%s)", key)
	}

	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(scanDeliveryBucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(jsonRaw),
	})
	if err != nil {
		return fmt.Errorf("error posting scan results to S3 - error: %s (%s)", err, key)
	} else {
		log.Printf("uploaded %s to bucket %s", key, scanDeliveryBucket)
		return nil
	}
}

// Uploadclusterroles -
func (s3RBACReporter *S3RBACReporter) Uploadclusterroles(clusterroles *rbac.ClusterRoleList, customer string, cluster string) error {
	key := customer + "/" + cluster + "/" + "clusterroles.json"
	scanDeliveryBucket := s3RBACReporter.S3Bucket
	if len(scanDeliveryBucket) == 0 {
		return fmt.Errorf("must configure S3_BUCKET")
	}
	jsonRaw, _ := json.Marshal(clusterroles)
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return fmt.Errorf("error configuring S3 client (%s)", key)
	}
	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(scanDeliveryBucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(jsonRaw),
	})
	if err != nil {
		return fmt.Errorf("error posting scan results to S3 - error: %s (%s)", err, key)
	} else {
		log.Printf("uploaded %s to bucket %s", key, scanDeliveryBucket)
		return nil
	}
}
