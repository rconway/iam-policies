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

# Simple example OPA policy rules

package example.tutorial.ractest

import rego.v1

default allow = false
allow if privileged

certs := http.send({
    "url": "http://iam-keycloak-operator-service:8080/realms/eoepca/protocol/openid-connect/certs",
    "method": "GET",
    "raise_error": false
})

default certs_error := null
certs_error := certs.error if {
    certs.error
}

jwks_code := certs.status_code

default jwks = null
jwks := certs.raw_body if {
    jwks_code == 200
}

default bearer_token = null
bearer_token := token if {
    some authKey in ["Authorization", "authorization"]
    [scheme, token] := split(input.request.headers[authKey], " ")
    lower(scheme) == "bearer"
}

default verified = false
verified := io.jwt.verify_rs256(bearer_token, jwks) if {
    bearer_token != null
    jwks != null
}

default claims = null
claims := io.jwt.decode(bearer_token)[1] if {
    verified
}

default privileged = false
privileged if {
    claims.preferred_username == data.policies.example.privileged_users[_]
}

debug := {
    "error": certs_error,
    "jwks_code": jwks_code,
    "token": bearer_token,
    "verified": verified,
    "claims": claims,
    "privileged": privileged
}

# 
# print("[zzz] cert_response: ", cert_response)
# 
# cert_response_code = cert_response.status_code
# 
# print("[zzz] cert_response_code: ", cert_response_code)
# 
# default verified_claims = null
# verified_claims := claims if {
#     print("[verified_claims] request: ", input.request)
#     some authKey in ["Authorization", "authorization"]
#     [type, token] := split(input.request.headers[authKey], " ")
#     type in ["Bearer", "bearer"]
#     io.jwt.verify_rs256(token, jwks) == true
#     claims := io.jwt.decode(token)[1]
# }
