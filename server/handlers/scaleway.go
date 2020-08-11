package handlers

import (
	"encoding/json"
	"github.com/go-resty/resty/v2"
	"github.com/scaleway/scaleway-sdk-go/api/instance/v1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"whitelister/utils"
)

type WhitelistScaleway struct {
	l *log.Logger
}

func NewWhitelistScaleway(l *log.Logger) *WhitelistScaleway{
	return &WhitelistScaleway{
		l: l,
	}
}

type WhitelistScalewayInputRule struct {
	Protocol     string `json:"protocol"`
	Direction    string `json:"direction"`
	Action       string `json:"action"`
	IPRange      string `json:"ip_range"`
	Position     string `json:"position"`
	DestPortFrom string `json:"dest_port_from"`
	DestPortTo   string `json:"dest_port_to"`
}

type WhitelistScalewayInput struct {
	Organization string                     `json:"organization"`
	Zone         scw.Zone                   `json:"zone"`
	AccessKey    string                     `json:"accessKey"`
	SecretKey    string                     `json:"secretKey"`
	SgID         string                     `json:"securityGroupID"`
	RuleID       string                     `json:"securityGroupRuleID"`
	Rule         WhitelistScalewayInputRule `json:"rules"`
}

type WhitelistScalewayOutput struct {
	Data  *instance.UpdateSecurityGroupRuleResponse `json:"data,omitempty"`
	Error string                                    `json:"error,omitempty"`
}

func (ws *WhitelistScaleway) WhitelistScaleway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	u := utils.New(ws.l)
	output := &WhitelistScalewayOutput{
		Data:  nil,
		Error: "",
	}

	input := &WhitelistScalewayInput{
		Organization: "",
		Zone:         "",
		AccessKey:    "",
		SecretKey:    "",
		SgID:         "",
		RuleID:       "",
		Rule:         WhitelistScalewayInputRule{
			Protocol:     "",
			Direction:    "",
			Action:       "",
			IPRange:      "",
			Position:     "",
			DestPortFrom: "",
			DestPortTo:   "",
		},
	}

	bodyBytes, bodyBytesErr := ioutil.ReadAll(r.Body)

	if bodyBytesErr != nil {
		ws.l.Errorf("Unable to read request Body. %s", bodyBytesErr.Error())
		output.Error = bodyBytesErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	inputErr := json.Unmarshal(bodyBytes, input)
	if inputErr != nil {
		ws.l.Errorf("Unable to parse request data. %s", inputErr.Error())
		output.Error = inputErr.Error()
		u.SendResponseJSON(output, w)
	}

	// Create a Resty Client
	restyClient := resty.New()

	resp, err := restyClient.R().EnableTrace().Get("https://api.ipify.org/?format=text")
	if err != nil {
		ws.l.Errorf("Error finding your current public IP. %s", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		output.Error = err.Error()
		u.SendResponseJSON(output, w)
		return
	}

	// Explore response object
	ws.l.Println("Response Info:")
	ws.l.Println("Error      :", err)
	ws.l.Println("Status Code:", resp.StatusCode())
	ws.l.Println("Status     :", resp.Status())
	ws.l.Println("Proto      :", resp.Proto())
	ws.l.Println("Time       :", resp.Time())
	ws.l.Println("Received At:", resp.ReceivedAt())
	ws.l.Println("Body       :\n", resp)
	ws.l.Println()

	// Explore trace info
	ws.l.Println("Request Trace Info:")
	ti := resp.Request.TraceInfo()
	ws.l.Println("DNSLookup    :", ti.DNSLookup)
	ws.l.Println("ConnTime     :", ti.ConnTime)
	ws.l.Println("TCPConnTime  :", ti.TCPConnTime)
	ws.l.Println("TLSHandshake :", ti.TLSHandshake)
	ws.l.Println("ServerTime   :", ti.ServerTime)
	ws.l.Println("ResponseTime :", ti.ResponseTime)
	ws.l.Println("TotalTime    :", ti.TotalTime)
	ws.l.Println("IsConnReused :", ti.IsConnReused)
	ws.l.Println("IsConnWasIdle:", ti.IsConnWasIdle)
	ws.l.Println("ConnIdleTime :", ti.ConnIdleTime)

	// Create a Scaleway client
	client, err := scw.NewClient(
		// Get your credentials at https://console.scaleway.com/account/credentials
		scw.WithDefaultOrganizationID(input.Organization),
		scw.WithAuth(input.AccessKey, input.SecretKey),
	)

	if err != nil {
		ws.l.Errorf("Error creating scaleway client. %s", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		output.Error = err.Error()
		u.SendResponseJSON(output, w)
		return
	}

	// Create SDK objects for Scaleway Instance product
	instanceApi := instance.NewAPI(client)

	proto := instance.SecurityGroupRuleProtocol(input.Rule.Protocol)
	direction := instance.SecurityGroupRuleDirection(input.Rule.Direction)
	action := instance.SecurityGroupRuleAction(input.Rule.Action)
	pos, posErr := strconv.ParseUint(input.Rule.Position, 10, 32)
	if posErr != nil {
		ws.l.Errorf("Error parsing Rule Position %s as UInt32. %s", input.Rule.Position, posErr.Error())
		http.Error(w, "Bad Request", http.StatusBadRequest)
		output.Error = posErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	pos32 := uint32(pos)

	destPortFrom, destPortFromErr := strconv.ParseUint(input.Rule.DestPortFrom, 10, 32)
	if destPortFromErr != nil {
		ws.l.Errorf("Error parsing DestPortFrom %s as UInt32. %s", input.Rule.DestPortFrom, destPortFromErr.Error())
		http.Error(w, "Bad Request", http.StatusBadRequest)
		output.Error = destPortFromErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	destPortFrom32 := uint32(destPortFrom)

	destPortTo, destPortToErr := strconv.ParseUint(input.Rule.DestPortTo, 10, 32)
	if destPortToErr != nil {
		ws.l.Errorf("Error parsing DestPortTo %s as UInt32. %s", input.Rule.DestPortTo, destPortToErr.Error())
		http.Error(w, "Bad Request", http.StatusBadRequest)
		output.Error = destPortToErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	destPortTo32 := uint32(destPortTo)

	//ip, ipr, iprErr := net.ParseCIDR(input.Rule.IPRange)
	ip, ipr, iprErr := net.ParseCIDR(resp.String() + "/32")
	if iprErr != nil {
		ws.l.Errorf("Error parsing  IP/IPRange %s/%s. %s", ip, input.Rule.IPRange, iprErr.Error())
		http.Error(w, "Bad Request", http.StatusBadRequest)
		output.Error = iprErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	ipRange := scw.IPNet{*ipr}

	updateSGRuleInput := &instance.UpdateSecurityGroupRuleRequest{
		Zone:                input.Zone,
		SecurityGroupID:     input.SgID,
		SecurityGroupRuleID: input.RuleID,
		Protocol:            &proto,
		Direction:           &direction,
		Action:              &action,
		IPRange:             &ipRange,
		Position:            &pos32,
		DestPortFrom:        &destPortFrom32,
		DestPortTo:          &destPortTo32,
	}

	sgs, sgsErr := instanceApi.UpdateSecurityGroupRule(updateSGRuleInput)
	if sgsErr != nil {
		ws.l.Errorf("Error updating Security group rule. %s", sgsErr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		output.Error = sgsErr.Error()
		u.SendResponseJSON(output, w)
		return
	}

	output.Data = sgs

	u.SendResponseJSON(output, w)
}