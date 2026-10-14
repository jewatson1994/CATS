"""Read-only Keycloak directory discovery for OIDC permission mapping suggestions."""

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .auth import oidc_configuration


PAGE_SIZE = 100
MAX_REQUESTS = 100
MAX_ITEMS = 5000
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
TOTAL_TIMEOUT = 45


class OidcDirectoryError(ValueError):
    """Safe, administrator-facing discovery failure."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def discover_oidc_directory(configuration: dict, ca_bundle: str | None = None) -> dict:
    """Return provider, candidates and warnings; never change provider or CATS roles.

    Candidates have kind, label, claim_path and expected_value. Only supported
    protocol mappers active in the login client's ID token produce suggestions.
    Directory membership still depends on the signing user's effective scopes.
    """
    config = oidc_configuration(configuration)
    issuer = config["issuer"]
    try:
        parsed = urllib.parse.urlsplit(issuer)
        match = re.fullmatch(r"(.*)/realms/([^/]+)", parsed.path)
        valid = (parsed.scheme in {"https", "http"} and parsed.hostname and
                 not parsed.username and not parsed.password and not parsed.query and
                 not parsed.fragment and match and parsed.port != 0)
    except ValueError:
        valid = False
    if not valid:
        raise OidcDirectoryError("Directory discovery supports Keycloak issuers ending in /realms/{realm}. Configure the server-side issuer or enter a claim mapping manually.")
    if any(urllib.parse.unquote(segment) in {".", ".."} or "/" in urllib.parse.unquote(segment) or "\\" in urllib.parse.unquote(segment)
           for segment in parsed.path.split("/")):
        raise OidcDirectoryError("The OIDC issuer contains an unsupported path. Check the Keycloak issuer URL.")
    if not config["client_id"] or not config["client_secret"]:
        raise OidcDirectoryError("Configure an OIDC client ID and client secret, and enable its Keycloak service account for directory discovery.")
    admin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                    match[1] + "/admin/realms/" + match[2], "", ""))
    try:
        context = ssl.create_default_context()
        if ca_bundle:
            context.load_verify_locations(**({"cadata": ca_bundle} if "BEGIN CERTIFICATE" in ca_bundle else {"cafile": ca_bundle}))
        opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=context))
    except (ValueError, OSError, ssl.SSLError):
        raise OidcDirectoryError("The OIDC CA bundle could not be loaded. Check the configured certificate bundle.") from None
    deadline = time.monotonic() + TOTAL_TIMEOUT
    requests = 0
    token = None

    def request_json(url, *, data=None):
        nonlocal requests
        remaining = deadline - time.monotonic()
        requests += 1
        if requests > MAX_REQUESTS or remaining <= 0:
            raise OidcDirectoryError("Directory discovery exceeded its request or time limit. Use a manual claim mapping for this directory.")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with opener.open(request, timeout=min(10, remaining)) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise OidcDirectoryError("Directory response exceeded the size limit. Use a manual claim mapping.")
                return json.loads(raw)
        except OidcDirectoryError:
            raise
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                message = "OIDC directory redirects are disabled to protect credentials. Configure the final server-side Keycloak issuer URL."
            elif data is not None and exc.code in {400, 401, 403}:
                message = "Keycloak rejected directory authentication. Check the client secret and enable service accounts and client authentication for the OIDC client."
            elif exc.code in {401, 403}:
                message = "Keycloak denied directory access; this does not mean the directory is empty. Give this client's service account read access with realm-management view-users, view-clients and view-realm (or equivalent fine-grained read permissions). Realm-admin is not required. Manual claim mapping and normal login remain available."
            else:
                message = f"Keycloak directory request returned HTTP {exc.code}. Check the issuer and Keycloak Admin REST API availability."
            raise OidcDirectoryError(message) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise OidcDirectoryError("Could not read the Keycloak directory. Check connectivity, the OIDC CA bundle and the provider's JSON response.") from None

    credentials = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": config["client_id"], "client_secret": config["client_secret"]}).encode()
    tokens = request_json(issuer + "/protocol/openid-connect/token", data=credentials)
    token = tokens.get("access_token") if isinstance(tokens, dict) else None
    if not isinstance(token, str) or not token or any(ord(c) < 32 for c in token):
        raise OidcDirectoryError("Keycloak did not return a usable service-account access token. Check the OIDC client's service-account configuration.")

    def get_list(path, **query):
        url = admin + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        result = request_json(url)
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise OidcDirectoryError("Keycloak returned an unexpected directory response. Check Admin REST API compatibility.")
        if len(result) > MAX_ITEMS:
            raise OidcDirectoryError("Directory discovery exceeded the item limit. Use a manual claim mapping.")
        return result

    def pages(path, **query):
        result = []
        while True:
            batch = get_list(path, first=len(result), max=PAGE_SIZE, **query)
            result.extend(batch)
            if len(result) > MAX_ITEMS:
                raise OidcDirectoryError("Directory discovery exceeded the item limit. Use a manual claim mapping.")
            if len(batch) < PAGE_SIZE:
                return result

    quote = lambda value: urllib.parse.quote(str(value), safe="")
    clients = pages("/clients", clientId=config["client_id"])
    clients = [client for client in clients if client.get("clientId") == config["client_id"]]
    if len(clients) != 1 or not clients[0].get("id"):
        raise OidcDirectoryError("The configured OIDC client was not found in the Keycloak directory. Check its client ID and service-account client-view permissions.")
    client_path = "/clients/" + quote(clients[0]["id"])
    mappers = get_list(client_path + "/protocol-mappers/models")
    scopes = get_list(client_path + "/default-client-scopes")
    optional = get_list(client_path + "/optional-client-scopes")
    requested = set(config["scopes"].split())
    scopes.extend(scope for scope in optional if scope.get("name") in requested)
    seen_scopes = set()
    for scope in scopes:
        scope_id = scope.get("id")
        if scope_id and scope_id not in seen_scopes:
            seen_scopes.add(scope_id)
            mappers.extend(get_list("/client-scopes/" + quote(scope_id) + "/protocol-mappers/models"))

    groups = []
    pending = pages("/groups", briefRepresentation="false")
    seen_groups = set()
    while pending:
        group = pending.pop()
        group_id = group.get("id")
        if not group_id or group_id in seen_groups:
            continue
        seen_groups.add(group_id)
        groups.append(group)
        if len(groups) > MAX_ITEMS:
            raise OidcDirectoryError("Directory discovery exceeded the group limit. Use a manual claim mapping.")
        # Embedded subGroups can be truncated; page children independently.
        if group.get("subGroupCount") != 0:
            pending.extend(pages("/groups/" + quote(group_id) + "/children", briefRepresentation="false"))
    realm_roles = pages("/roles")
    client_roles = pages(client_path + "/roles")
    candidates = []
    warnings = ["Suggestions reflect configured ID-token mappers. Effective user roles, client scope restrictions and custom mappers can change the claims emitted at login; verify a user's ID-token claims before granting permissions."]
    mapper_types = {"oidc-group-membership-mapper": "group", "oidc-usermodel-realm-role-mapper": "realm_role", "oidc-usermodel-client-role-mapper": "client_role"}
    covered = set()
    seen_candidates = set()
    for mapper in mappers:
        kind = mapper_types.get(mapper.get("protocolMapper"))
        settings = mapper.get("config") or {}
        if not kind or not isinstance(settings, dict) or str(settings.get("id.token.claim")).lower() != "true":
            continue
        path = settings.get("claim.name")
        if not isinstance(path, str) or not path:
            continue
        if kind == "client_role":
            mapped_client = settings.get("usermodel.clientRoleMapping.clientId")
            if mapped_client and mapped_client != config["client_id"]:
                continue
            if "${client_id}" in path and any(char in config["client_id"] for char in ".\\"):
                warnings.append("A client role claim uses a client ID containing dots or escapes; enter that mapping manually after inspecting the token.")
                continue
            path = path.replace("${client_id}", config["client_id"])
        if len(path) > 240 or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", path):
            warnings.append("A provider claim path cannot be represented by CATS claim mappings; inspect the token and adjust the provider mapper or enter a supported path manually.")
            continue
        if kind != "group" and str(settings.get("multivalued")).lower() != "true":
            continue
        covered.add(kind)
        items = groups if kind == "group" else realm_roles if kind == "realm_role" else client_roles
        for item in items:
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            value = name
            if kind == "group" and str(settings.get("full.path")).lower() == "true":
                value = item.get("path")
                if not isinstance(value, str) or not value.startswith("/"):
                    continue
            elif kind != "group":
                prefix_key = "usermodel.realmRoleMapping.rolePrefix" if kind == "realm_role" else "usermodel.clientRoleMapping.rolePrefix"
                prefix = str(settings.get(prefix_key) or "")
                if kind == "client_role" and not settings.get("usermodel.clientRoleMapping.clientId"):
                    prefix = prefix.replace("${client_id}", config["client_id"])
                value = prefix + name
            if not value or value != value.strip() or len(value) > 300:
                warnings.append("A provider group or role value cannot be represented by CATS claim mappings and was omitted (values must be nonempty, at most 300 characters and have no surrounding whitespace).")
                continue
            key = (kind, path, value)
            if key not in seen_candidates:
                seen_candidates.add(key)
                candidates.append({"kind": kind, "label": str(item.get("path") or name) if kind == "group" else name, "claim_path": path, "expected_value": value})
                if len(candidates) > MAX_ITEMS:
                    raise OidcDirectoryError("Directory discovery exceeded the suggestion limit. Use a manual claim mapping.")
    for kind, label in (("group", "groups"), ("realm_role", "realm roles"), ("client_role", "client roles")):
        if kind not in covered:
            warnings.append(f"No supported active ID-token mapper was found for {label}. Enable an ID-token mapper (multivalued for roles) on the login client or a requested client scope, or enter the claim mapping manually.")
    return {"provider": "keycloak", "candidates": sorted(candidates, key=lambda item: (item["kind"], item["label"], item["claim_path"])), "warnings": list(dict.fromkeys(warnings)),
            "directory_counts": {"groups": len(groups), "realm_roles": len(realm_roles), "client_roles": len(client_roles)}}
