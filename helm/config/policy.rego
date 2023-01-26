package envoy.authz

import input.attributes.request.http as http_request
import input.attributes.metadataContext.filterMetadata["envoy.filters.http.jwt_authn"].map_colonies_token_payload as payload
import input.attributes.metadataContext.filterMetadata.map_colonies as map_colonies

default allow = false

### Resources Access ###
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
