# Copyright 2024 Werum Software & Systems AG (Germany)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# Utility rules

package eoepca.iam.util

import rego.v1

# Makes available the JWKS of the EOEPCA realm in Keycloak (generic).
#
# "iam-keycloak" is the Bitnami Keycloak
# "iam-core-keycloak-operator-service" (port 8080) is the Keycloak Operator's. 
# NOTE: Once the RKE1 cluster is deprecated, this will be removed.

keycloak_jwks_urls := [
    "http://iam-keycloak/realms/eoepca/protocol/openid-connect/certs",
    "http://iam-core-keycloak-operator-service:8080/realms/eoepca/protocol/openid-connect/certs",
    "http://iam-keycloak-operator-service:8080/realms/eoepca/protocol/openid-connect/certs"
]

# keycloak_jwks_urls := [
#     "http://iam-keycloak-operator-service:8080/realms/eoepca/protocol/openid-connect/certs"
# ]

jwks_request(url) := http.send({
    "url": url,
    "method": "GET",
    "timeout": "500ms",
    "force_cache": true,
    "force_cache_duration_seconds": 3600, # Cache response for an hour
    "raise_error": false # try the next candidate instead of aborting evaluation
})

jwks := response.raw_body if {
    some url in keycloak_jwks_urls
    response := jwks_request(url)
    response.status_code == 200
}

# Claims from JWT if JWT is present and can be verified; null otherwise
# This rule is only useful for policies that accept the APISIX OPA input format.
default verified_claims = null
verified_claims := claims if {
    print("[verified_claims] request: ", input.request)
    some authKey in ["Authorization", "authorization"]
    [type, token] := split(input.request.headers[authKey], " ")
    type in ["Bearer", "bearer"]
    io.jwt.verify_rs256(token, jwks) == true
    claims := io.jwt.decode(token)[1]
}