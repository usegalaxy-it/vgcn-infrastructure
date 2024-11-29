#!/usr/bin/env bash
export OS_AUTH_URL=https://keystone.recas.ba.infn.it/v3
export OS_AUTH_TYPE=v3oidcaccesstoken
export OS_PROJECT_ID=de43ed139278425c981263c90e39f18e
export OS_TENANT_ID=de43ed139278425c981263c90e39f18e
export OS_PROTOCOL="openid"
export OS_IDENTITY_PROVIDER="recas-bari"
export OS_IDENTITY_API_VERSION=3
export OS_REGION_NAME="RegionOne"
export OS_INTERFACE=public
export OIDC_AGENT_ACCOUNT=lma
export OS_ACCESS_TOKEN=$(oidc-token ${OIDC_AGENT_ACCOUNT})
export OS_AUTH_TOKEN=$OS_ACCESS_TOKEN
echo $OS_AUTH_TOKEN
export IAM_ACCESS_TOKEN=$OS_ACCESS_TOKEN
