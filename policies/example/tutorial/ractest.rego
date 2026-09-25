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

default allow = true

allow = true

print("[zzz] input request: ", input.request)

cert_response := http.send({
    "url": "http://iam-keycloak-operator-service:8080/realms/eoepca/protocol/openid-connect/certs",
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 3600 # Cache response for an hour
})

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
