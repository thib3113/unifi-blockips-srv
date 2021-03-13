# unifi-blockips-srv

#TODO
- write a readme

## WARNING

This script was never use in real case for the moment, only testing .


# Brief

## ENV

| key | description | mandatory |
|--|--|--
| UNIFI_CONTROLLER_IP | the ip of the controller ( or fqdn ) | yes
| UNIFI_CONTROLLER_PORT | port of the controller sometimes 8443 or 443| yes
| UNIFI_USERNAME | username of a user ( rights levels not tested ) | yes
| UNIFI_PASSWORD | password of the user | yes
| UNIFI_SITE_NAME | name of the "site" | no (default to first one)
| UNIFI_FW_RULE_NAME | name of the FW Rule | yes
| UNIFI_GROUP_NAME | group where the ips will be managed | yes
| ADD_CHECKSUM | sha256 of the token to add ip | no ( but recommended )
| RM_CHECKSUM | sha256 of the token to add ip | no (default to ADD_CHECKSUM, recommended)
| port | the port where the app will listen | yes (for the moment)


# How to use

To add an IP to the blocklist :
`POST /?token=tatayoyo&ips[]=127.0.0.1`

to delete an IP
`DELETE /?token=tatayoyo2&ips[]=127.0.0.1`

token will be check again ADD_CHECKSUM or RM_CHECKSUM . You can use this site to generate your checksum : https://emn178.github.io/online-tools/sha256.html

To secure data in the container, you can pass ENV via `/app/.env` ( respecting .env format ) .

# How to block the Ips
You can see this : https://github.com/tusc/blockips-unifi#preparation
You can reuse the firewall part, create the rule, create the group .

In this script, 
`UNIFI_FW_RULE_NAME` will be `Scheduled Block Group`
and
`UNIFI_GROUP_NAME` will be `Block_Group`
