package httpapi

test_health_allowed {
  allow with input as {"method": "GET", "path": "/health", "subject": "anonymous", "scopes": []}
}

test_login_allowed {
  allow with input as {"method": "POST", "path": "/login", "subject": "anonymous", "scopes": []}
}

test_user_denied_without_scope {
  not allow with input as {"method": "GET", "path": "/user", "subject": "user", "scopes": []}
}

test_user_allowed_with_scope {
  allow with input as {"method": "GET", "path": "/user", "subject": "user", "scopes": ["user:read"]}
}
