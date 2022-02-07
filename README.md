# Whitelister
A tool to whitelist your IP on a cloud provider.

Requires Docker Compose 2.x

### Routes

```
GET /ping
```
Provides apllication version information

```
GET /
```
A basic Hello World route. Doesn't do much.

```
POST /list/securityGroups
```
Lists your security groups

- _Currently supports Scaleway only_

Sample Request Payload
```
{
"zone":"fr-par-1", // your zone could be different
"sg_name":"SG-NAME",
"organization":"YOUR-SCALEWAY-ORG-ID",
"accessKey":"YOUR-ACCESS-KEY",
"secretKey":"YOUR-SECRET-KEY",
"maxResults":100,
"pageNumber":1
}
```

Please make a request yourself to see the response.

```
POST /whitelist/scaleway
```
Sample Request Payload

```
{
    "zone":"fr-par-1", // your zone could be different
    "organization":"YOUR-SCALEWAY-ORG-ID",
    "accessKey":"YOUR-ACCESS-KEY",
    "secretKey":"YOUR-SECRET-KEY",
    "securityGroupID":"Scaleway security group ID you wish to modify",
    "securityGroupRuleID":"Scaleway security group rule ID you wish to modify",
    "rules":{
	    "position":"Position of your rule",
	    "protocol": "Protocol for your Rule", // "TCP", "UDP" etc.
	    "direction":"inbound", // "inbound" or "outbound" direction
	    "action":"accept", // "accept" or "reject" action to be taken
        // IP to be whitelisted. Not supported currently. Your IP is automatically fetched from "https://api.ipify.org/?format=text"
	    "ip_range":"1.1.1.1",
        // Port-range Start
	    "dest_port_from":"3306",
        // Port-range end
	    "dest_port_to":"3306"
    }
}
```

Provide your details and make a request to see the response.
