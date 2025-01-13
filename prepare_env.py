#!/usr/bin/env python3

import subprocess
import os
import yaml
from jinja2 import Template

def main():
    with open("secrets.yaml", "r") as sf:
        secrets = yaml.safe_load(sf)

    openstack_data = secrets.get("openstack", {})
    oidc_account = openstack_data.get("OIDC_AGENT_ACCOUNT", "")

    token = get_oidc_token(oidc_account)
    print("[INFO] OIDC token obtained (first chars):", token[:30], "...")

    template_params = {
        "auth_type":           openstack_data.get("OS_AUTH_TYPE", ""),
        "identity_api_version": openstack_data.get("OS_IDENTITY_API_VERSION", ""),
        "region_name":         openstack_data.get("OS_REGION_NAME", ""),
        "interface":           openstack_data.get("OS_INTERFACE", ""),
        "auth_url":            openstack_data.get("OS_AUTH_URL", ""),
        "project_id":          openstack_data.get("OS_PROJECT_ID", ""),
        "identity_provider":   openstack_data.get("OS_IDENTITY_PROVIDER", ""),
        "protocol":            openstack_data.get("OS_PROTOCOL", ""),
        "access_token":        token
    }

    with open("clouds.yaml.j2", "r") as tf:
        template_content = tf.read()
    template = Template(template_content)
    rendered = template.render(**template_params)

    with open("clouds.yaml", "w") as out_yaml:
        out_yaml.write(rendered)

    print("[INFO] clouds.yaml created successfully.")

def get_oidc_token(account):
    try:
        result = subprocess.run(
            ["oidc-token", account],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print("[ERROR] Could not obtain OIDC token:", e.stderr)
        raise

if __name__ == "__main__":
    main()

