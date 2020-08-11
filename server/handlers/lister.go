package handlers

import (
	"encoding/json"
	"github.com/scaleway/scaleway-sdk-go/api/instance/v1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"io/ioutil"
	"whitelister/utils"
	//"github.com/scaleway/scaleway-sdk-go/utils"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type Lister struct {
	l *log.Logger
}

func NewLister(l *log.Logger) *Lister{
	return &Lister{
		l: l,
	}
}

type ScalewaySGInput struct {
	Organization string  `json:"organization"`
	Zone         scw.Zone `json:"zone"`
	AccessKey    string   `json:"accessKey"`
	SecretKey    string   `json:"secretKey"`
	Name         string  `json:"sg_name"`
	PerPage      uint32  `json:"maxResults"`
	Page         int32   `json:"pageNumber"`
}

type ScalewaySGOutputData struct {
	SecurityGroup *instance.ListSecurityGroupsResponse
	SecurityGroupRules *instance.ListSecurityGroupRulesResponse
}

type ScalewaySGOutput struct {
	Data  *ScalewaySGOutputData `json:"data,omitempty"`
	Error string                `json:"error,omitempty"`
}

func (ls *Lister) ScalewaySG(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	output := &ScalewaySGOutput{
		Error: "",
		Data: &ScalewaySGOutputData{
			SecurityGroup:      nil,
			SecurityGroupRules: nil,
		},
	}

	u := utils.New(ls.l)

	bodyBytes, bodyBytesErr := ioutil.ReadAll(r.Body)

	if bodyBytesErr != nil {
		ls.l.Errorf("Unable to read request Body. %s", bodyBytesErr.Error())
		output.Error = bodyBytesErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	request := &ScalewaySGInput{
		Organization: "",
		Zone:         "",
		AccessKey:    "",
		SecretKey:    "",
		Name:         "",
		PerPage:      1000,
		Page:         1,
	}

	requestErr := json.Unmarshal(bodyBytes, request)
	if requestErr != nil {
		ls.l.Errorf("Unable to parse request data. %s", requestErr.Error())
		output.Error = requestErr.Error()
		u.SendResponseJSON(output, w)
	}

	ls.l.Infof("Unmarshalled Request: %#v", request)

	input := &instance.ListSecurityGroupsRequest{
		Zone:         request.Zone,
		Name:         scw.StringPtr(request.Name),
		Organization: scw.StringPtr(request.Organization),
		PerPage:      scw.Uint32Ptr(request.PerPage),
		Page:         scw.Int32Ptr(request.Page),
	}

	// Create a Scaleway client
	client, err := scw.NewClient(
		// Get your credentials at https://console.scaleway.com/account/credentials
		scw.WithDefaultOrganizationID(request.Organization),
		scw.WithAuth(request.AccessKey, request.SecretKey),
	)

	if err != nil {
		ls.l.Errorf("Error creating scaleway client. %s", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		output.Error = err.Error()
		u.SendResponseJSON(output, w)
		return
	}

	// Create SDK objects for Scaleway Instance product
	instanceApi := instance.NewAPI(client)

	sgs, sgsErr := instanceApi.ListSecurityGroups(input)

	if sgsErr != nil {
		ls.l.Errorf("Error Reading Security Groups from Scaleway. %s", sgsErr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		output.Error = sgsErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	output.Data.SecurityGroup = sgs
	
	sgRulesInput := &instance.ListSecurityGroupRulesRequest{
		Zone:            sgs.SecurityGroups[0].Zone,
		SecurityGroupID: sgs.SecurityGroups[0].ID,
		PerPage:         scw.Uint32Ptr(request.PerPage),
		Page:            scw.Int32Ptr(request.Page),
	}
	
	sgRules, sgRulesErr := instanceApi.ListSecurityGroupRules(sgRulesInput)
	if sgRulesErr != nil {
		ls.l.Errorf("Error reading rules for security group %s (%s)", sgs.SecurityGroups[0].Name, sgs.SecurityGroups[0].ID)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		output.Error = sgRulesErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	output.Data.SecurityGroupRules = sgRules

	u.SendResponseJSON(output, w)
}