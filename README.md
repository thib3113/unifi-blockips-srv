# unifi-blockips-srv

[![Docker Pulls](https://img.shields.io/docker/pulls/thib3113/unifi-blockips-srv.svg)](https://hub.docker.com/r/thib3113/unifi-blockips-srv)

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
| port | the port where the app will listen | no (default to 3000)


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

# How to run the app

## Docker
the image is built automatically for `linux/amd64`,`linux/arm64` and `linux/arm/v7` (so in theory compatible with raspberry pi and other arm IoT)

`docker run thib3113/unifi-blockips-srv`

or with docker compose / swarm:

### compose
```yaml
version: '3.7'
services:
  unifi-blocker:
    image: thib3113/unifi-blockips-srv:latest
    environment:
      PORT: 3000
      UNIFI_CONTROLLER_URL: http://unifi
      UNIFI_SITE_NAME: my_site
      UNIFI_FW_RULE_NAME: my_block_rule
      UNIFI_GROUP_NAME: my_group
      ADD_CHECKSUM: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
      RM_CHECKSUM: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
      # please never set the username / password like that, bind a file to /.env with the variables
      UNIFI_USERNAME: username
      UNIFI_PASSWORD: superPassword
```

### swarm
```yaml
version: '3.7'
services:
  unifi-blocker:
    image: thib3113/unifi-blockips-srv:latest
    secrets:
      - source: UNIFI_BLOCKER_ENV
        target: /app/.env
    environment:
      PORT: 3000
```

## PM2

[read more about PM2](https://pm2.keymetrics.io/)

```shell
git clone git@github.com:thib3113/unifi-blockips-srv.git
npm run build
pm2 start
```

# Configurations for [EDR](https://en.wikipedia.org/wiki/Endpoint_detection_and_response)
## Crowdsec
- use [custom bouncer](https://github.com/crowdsecurity/cs-custom-bouncer)
- use a script like :


```shell
#!/bin/bash

IP=$2
DURATION=$3
REASON=$4
JSON_OBJECT=$5

#change this URL by the url to access this script
URL=http://unifi-blocker-ip:3000

#change tokens in the urls

LOG=/var/log/bouncer.log

case $1 in
  add)
    #here the code for the add command
    #echo add ${IP} for ${DURATION}s because "${REASON}" json : ${JSON} >> ${LOG}
    /usr/bin/curl -k --location --request POST "${URL}?token=amldfksqmldk&ips=${IP}"
  ;;
  del)
    #here the code for the del command
    #echo del ${IP} for ${DURATION}s because "${REASON}" json : ${JSON} >> ${LOG}
    /usr/bin/curl -k --silent --location --request DELETE "${URL}?token=qsdazekrlsfdlm&ips=${IP}"
  ;;
  *) echo "unknown action $1" >> ${LOG}
     exit 1;;
esac
```

## fail2ban

`/etc/fail2ban/action.d/unifi-ban.conf` :
```
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /usr/bin/curl -k -v --location --request POST 'http://unifi-blocker-ip:3000?token=amldfksqmldk&ips=<ip>'
actionunban = /usr/bin/curl -k -v --silent --location --request DELETE 'http://unifi-blocker-ip:3000?token=qsdazekrlsfdlm&ips=<ip>'
```

`/etc/fail2ban/jail.d/your-jail.local` :

```
[your-jail]
banaction = unifi-ban
```