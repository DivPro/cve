# CVE
## vulnerabilities aggregation service

[![Build Status](https://travis-ci.com/DivPro/cve.svg?branch=master)](https://travis-ci.com/DivPro/cve)

### sources
* debian :heavy_check_mark: [link](https://security-tracker.debian.org/tracker/) 
* redhat :heavy_check_mark: [link](https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/index) 
* ubuntu [planned] [link](https://git.launchpad.net/ubuntu-cve-tracker)
* NVD [planned] [link](https://nvd.nist.gov/)

### service dependencies
* Go compiler - project source codes 
* Postgresql - data store and locks

### CI/CD dependecies
* GNU make - cli unification
* docker - for standalone launch
* SQL migrations - bundled

### HTTP API
method | url | description
--- | --- | ---
GET | [/api/update](#) | update sources
GET | [/api/cve/{cve}?source={source}&pkg={package}](#) | search cve information

## internals
### project structure
* Makefile - make definitions
* Dockerfile - build docker image
* docker-compose.yml - build infra dependencies and start service
* main/cve - entrypoint, reads configuration and starts app
* migrations - DB DDL statements
* internal/app - pp init
* internal/app/handlers - http handler sources
* internal/config - app config definition and validation
* internal/entity - DB layer abstrations and models
* internal/service - application layer main logic
* internal/service/update/source - cve sources api adapters
### startup configuration params
param | type | default | description
--- | --- | --- | ---
http_addr | cli | 0.0.0.0 | addr for incoming http connections
http_port | cli | 80 | port for incoming http connections
log_level | cli | info | logging level
DB_CONN | env | docker-compose | postgresql dsn
