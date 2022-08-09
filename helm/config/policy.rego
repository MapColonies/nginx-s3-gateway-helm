package envoy.authz

import input.attributes.request.http as http_request
import input.parsed_query as query_params
import input.attributes.metadataContext.filterMetadata.map_colonies as map_colonies

default allow = false

# Gets the token form query
jwt_token = token {
  token := io.jwt.decode(query_params.token[0])
}

# Gets the token form header
{{- if .Values.authentication.opa.customHeaderName }}
jwt_token = token {
  token := io.jwt.decode(http_request.headers[{{ .Values.authentication.opa.customHeaderName | lower | quote }}])
}
{{- end }}

# Extract payload from token
payload = payload {
  [_, payload, _] := jwt_token
}

# Check domain
user_has_resource_access[payload] {
  lower(payload.d[_]) = lower(map_colonies.domain)
}

# Check if origin is in allowed origins array
valid_origin[payload] {
  payload.ao[_] = http_request.headers.origin
}

# Check in case that allowed origin is not an array
valid_origin[payload] {
  payload.ao == http_request.headers.origin
}

# Check in case that there is no allowed origin
valid_origin[payload] {
  not payload.ao
}

# Allow authenticated access
allow {
  valid_origin[payload]
  user_has_resource_access[payload]
}

# Allow cors preflight WITHOUT AUTHENTICATION
allow {
  http_request.method == "OPTIONS"
  _ = http_request.headers["access-control-request-method"]
  _ = http_request.headers["access-control-request-headers"]
}
