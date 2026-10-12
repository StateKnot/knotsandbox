"""Initial Keycloak realm only. Never used to update an existing realm."""


def execution(authenticator, requirement="REQUIRED", priority=10, flow=False):
    return {"authenticator": authenticator, "requirement": requirement,
            "priority": priority, "authenticatorFlow": flow, "userSetupAllowed": False}


def flow(alias, executions, top=True):
    return {"alias": alias, "providerId": "basic-flow", "topLevel": top,
            "builtIn": False, "authenticationExecutions": executions}


def build(settings):
    forms = execution(None, "ALTERNATIVE", 30, True)
    forms.pop("authenticator")
    forms["flowAlias"] = "sandbox-password-and-otp"
    realm = {
        "realm": settings["realm"], "enabled": True, "sslRequired": "all",
        "registrationAllowed": False, "registrationEmailAsUsername": False,
        "duplicateEmailsAllowed": False, "verifyEmail": True,
        "resetPasswordAllowed": True, "editUsernameAllowed": False,
        "bruteForceProtected": True, "permanentLockout": False,
        "failureFactor": 5, "waitIncrementSeconds": 60, "maxFailureWaitSeconds": 900,
        "accessTokenLifespan": 300, "accessTokenLifespanForImplicitFlow": 300,
        "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 28800,
        "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        "defaultSignatureAlgorithm": "RS256",
        "passwordPolicy": "length(14) and notUsername(undefined) and notEmail(undefined) and passwordHistory(5)",
        "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA256",
        "otpPolicyDigits": 6, "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1,
        "browserFlow": "sandbox-browser-mfa",
        "authenticationFlows": [
            flow("sandbox-browser-mfa", [execution("auth-cookie", "ALTERNATIVE"),
                  execution("identity-provider-redirector", "ALTERNATIVE", 20), forms]),
            flow("sandbox-password-and-otp", [execution("auth-username-password-form"),
                  execution("auth-otp-form", priority=20)], False),
            # A duplicate username/email fails. It is never auto-linked to an existing account.
            flow("sandbox-first-broker", [execution("idp-create-user-if-unique")]),
            flow("sandbox-post-broker-mfa", [execution("auth-otp-form")]),
        ],
        "requiredActions": [
            {"alias": action, "name": action, "providerId": action,
             "enabled": True, "defaultAction": action in {"CONFIGURE_TOTP", "VERIFY_EMAIL"},
             "priority": index * 10}
            for index, action in enumerate(["CONFIGURE_TOTP", "VERIFY_EMAIL", "UPDATE_PASSWORD", "UPDATE_PROFILE"])
        ],
        "smtpServer": {"host": settings["smtp"]["host"], "port": "587", "from": settings["smtp"]["from"],
                       "auth": "true", "starttls": "true", "ssl": "false",
                       "user": "${SMTP_USERNAME}", "password": "${SMTP_PASSWORD}"},
        "eventsEnabled": True, "eventsExpiration": 604800,
        "adminEventsEnabled": True, "adminEventsDetailsEnabled": False,
        "clientScopes": [{"name": "sandbox:access", "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
            "protocolMappers": [{"name": "sandbox-api-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                "config": {"included.custom.audience": settings["audience"],
                           "id.token.claim": "false", "access.token.claim": "true",
                           "userinfo.token.claim": "false", "introspection.token.claim": "true"}}]}],
        "clients": [{"clientId": "admin-cli", "enabled": False, "directAccessGrantsEnabled": False,
                     "implicitFlowEnabled": False, "standardFlowEnabled": False}], "users": [],
    }
    broker = settings.get("broker")
    if broker:
        realm["identityProviders"] = [{"alias": "enterprise", "providerId": "oidc", "enabled": True,
            "trustEmail": False, "storeToken": False, "linkOnly": False,
            "firstBrokerLoginFlowAlias": "sandbox-first-broker", "postBrokerLoginFlowAlias": "sandbox-post-broker-mfa",
            "config": {"issuer": broker["issuer"], "authorizationUrl": broker["authorization_url"],
                "tokenUrl": broker["token_url"], "jwksUrl": broker["jwks_url"],
                "clientId": broker["client_id"], "clientSecret": "${BROKER_SECRET}",
                "clientAuthMethod": "client_secret_post", "validateSignature": "true",
                "useJwksUrl": "true", "defaultScope": "openid profile email",
                "syncMode": "IMPORT", "pkceEnabled": "true", "pkceMethod": "S256"}}]
    return realm


def subject_mapper():
    """Exact non-pairwise access-token subject; explicit scopes do not inherit basic."""
    return {"name": "sandbox-subject", "protocol": "openid-connect",
            "protocolMapper": "oidc-sub-mapper", "consentRequired": False,
            "config": {"access.token.claim": "true", "introspection.token.claim": "true"}}


def machine_client(client_id):
    """Admin API request template; secret value comes from the caller's secret manager."""
    return {"clientId": client_id, "protocol": "openid-connect", "enabled": True,
            "publicClient": False, "clientAuthenticatorType": "client-jwt",
            "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False, "defaultClientScopes": ["sandbox:access"],
            "optionalClientScopes": [], "protocolMappers": [subject_mapper()],
            "attributes": {"access.token.lifespan": "300", "use.jwks.url": "false",
                           "jwt.credential.certificate": "REPLACE_WITH_CLIENT_PUBLIC_X509_DER_BASE64",
                           "token.endpoint.auth.signing.alg": "RS256"}}
