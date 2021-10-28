package rbacreporter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	rbacutils "github.com/armosec/rbac-utils/rbacutils"
	"github.com/gofrs/uuid"
)

type EventReceiverRBACReporter struct {
	EventReceiverURL string
	httpClient       http.Client
	host             url.URL
	customerGUID     string
	clusterName      string
}

func NewEventReceiverRBACReporter(eventReceiverURL string, customerGUID string, clusterName string) *EventReceiverRBACReporter {
	hostURL := initEventReceiverURL(eventReceiverURL, customerGUID, clusterName)
	return &EventReceiverRBACReporter{
		EventReceiverURL: eventReceiverURL,
		httpClient:       http.Client{},
		host:             *hostURL,
		customerGUID:     customerGUID,
		clusterName:      clusterName,
	}
}

func (eventReceiverRBACReporter *EventReceiverRBACReporter) GetClusterName() string {
	return eventReceiverRBACReporter.clusterName
}

func (eventReceiverRBACReporter *EventReceiverRBACReporter) GetCustomerGUID() string {
	return eventReceiverRBACReporter.customerGUID
}

func (eventReceiverRBACReporter *EventReceiverRBACReporter) SetClusterName(clusterName string) {
	eventReceiverRBACReporter.clusterName = clusterName
}

func (eventReceiverRBACReporter *EventReceiverRBACReporter) SetCustomerGUID(customerGUID string) {
	eventReceiverRBACReporter.customerGUID = customerGUID
}

func (eventReceiverRBACReporter *EventReceiverRBACReporter) ReportRbac(rbacObj *rbacutils.RbacObjects) error {
	err := eventReceiverRBACReporter.SendRbacObjects(rbacObj)
	return err
}

func initEventReceiverURL(host string, customerGUID string, clusterName string) *url.URL {
	urlObj := url.URL{}
	scheme := "https"
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
		scheme = "http"
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
		scheme = "https"
	}
	urlObj.Scheme = scheme
	urlObj.Host = host
	urlObj.Path = "/k8s/postureReport" // TODO: change path to rbac
	q := urlObj.Query()
	q.Add("customerGUID", uuid.FromStringOrNil(customerGUID).String())
	q.Add("clusterName", clusterName)
	urlObj.RawQuery = q.Encode()
	return &urlObj
}

func (eventReceiverRBACReporter *EventReceiverRBACReporter) SendRbacObjects(rbacObj *rbacutils.RbacObjects) error {
	reqBody, err := rbacObj.MarshalJSON()
	if err != nil {
		return fmt.Errorf("in 'Send' failed to json.Marshal, reason: %v", err)
	}
	host := hostToString(&eventReceiverRBACReporter.host)

	req, err := http.NewRequest("POST", host, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("in 'Send', http.NewRequest failed, host: %s, reason: %v", eventReceiverRBACReporter.host.String(), err)
	}
	res, err := eventReceiverRBACReporter.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("httpClient.Do failed: %v", err)
	}
	msg, err := httpRespToString(res)
	if err != nil {
		return fmt.Errorf("%v:%s", err, msg)
	}
	return err
}

// HTTPRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
func httpRespToString(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	strBuilder := strings.Builder{}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		strBuilder.Grow(int(resp.ContentLength))
	}
	_, err := io.Copy(&strBuilder, resp.Body)
	if err != nil {
		return strBuilder.String(), err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("response status: %d. Content: %s", resp.StatusCode, strBuilder.String())
	}
	return strBuilder.String(), err
}

func hostToString(host *url.URL) string {
	q := host.Query()
	host.RawQuery = q.Encode()
	return host.String()
}
