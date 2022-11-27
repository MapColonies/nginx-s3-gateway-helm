package envoy.authz

import input.attributes.request.http as http_request
import input.attributes.metadataContext.filterMetadata["envoy.filters.http.jwt_authn"].map_colonies_token_payload as payload
import input.attributes.metadataContext.filterMetadata.map_colonies as map_colonies

# Decline until I allow it.
default allow = false 

### Resources Access ###
user_has_resource_access[payload] {
  lower(payload.d[_]) = lower(map_colonies.domain)
}
### Resources Access ###

### ORIGIN ###
# Checks if origin is in allowed origin
valid_origin[payload] {
  payload.ao[_] = http_request.headers.origin
}

# Checks if origin is allowed origin (if ao is not an arr)
valid_origin[payload] {
  payload.ao == http_request.headers.origin
}

# Checks if there is allowed origin
valid_origin[payload] {
  not payload.ao
}
### ORIGIN ###

# allow authenticated access
allow {
  valid_origin[payload]
  user_has_resource_access[payload]
}

# allow cors preflight WITHOUT AUTHENTICATION
allow {
  http_request.method == "OPTIONS"
  _ = http_request.headers["access-control-request-method"]
  _ = http_request.headers["access-control-request-headers"]
}
