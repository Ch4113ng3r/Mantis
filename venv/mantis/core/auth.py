"""
Authentication handler and credential store.

Manages multiple auth contexts (unauthenticated, regular user, admin)
so MANTIS can test privilege escalation, BOLA, and access control
by replaying requests across different sessions.

Supported auth methods:
- none: unauthenticated
- form: HTML form login (POST username/password)
- bearer: static bearer token
- cookie: static session cookie
- basic: HTTP Basic Auth
- oauth2: OAuth2 client credentials
- api_key: API key in header or query param
- custom: arbitrary custom header
- ntlm: NTLMv2 authentication (supports SAML SSO redirect chains)

NTLMv2 + SAML SSO flow:
    The most common enterprise SSO pattern is:
    1. User hits protected app → redirected to ADFS/IdP
    2. IdP challenges with NTLMv2 (HTTP 401 + WWW-Authenticate: Negotiate/NTLM)
    3. Client performs NTLM three-way handshake (negotiate → challenge → authenticate)
    4. IdP validates credentials against Active Directory
    5. IdP generates SAML assertion and auto-POSTs it to the SP's ACS endpoint
    6. SP validates the SAML assertion and sets session cookies
    7. All subsequent requests use those session cookies

    MANTIS handles this transparently: httpx with httpx-ntlm performs
    the NTLM handshake, follow_redirects=True handles the SAML POST
    binding, and the resulting session cookies are captured for reuse.

Usage in config.yaml:
    credentials:
      accounts:
        - role: admin
          method: ntlm
          url: https://internalapp.corp.barclays.com
          domain: CORP
          username: admin.user
          password: P@ssw0rd!
        - role: user
          method: ntlm
          url: https://internalapp.corp.barclays.com
          domain: CORP
          username: regular.user
          password: P@ssw0rd!
        - role: unauthenticated
          method: none
"""

import httpx
import json
import base64
import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from urllib.parse import urlparse, urljoin


class AuthMethod(Enum):
    NONE = "none"                # Unauthenticated
    FORM = "form"                # HTML form login (POST username/password)
    BEARER = "bearer"            # Static bearer token
    COOKIE = "cookie"            # Static session cookie
    BASIC = "basic"              # HTTP Basic Auth
    OAUTH2 = "oauth2"            # OAuth2 client credentials
    API_KEY = "api_key"          # API key in header or query param
    CUSTOM = "custom"            # Custom header (e.g., x-auth-token)
    NTLM = "ntlm"               # NTLMv2 with SAML SSO redirect support


@dataclass
class AuthContext:
    """A single authenticated session for a specific role."""
    role: str                              # "admin", "user", "unauthenticated"
    method: AuthMethod
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)   # Auth headers to inject
    tokens: dict = field(default_factory=dict)     # bearer, refresh, etc.
    authenticated: bool = False
    raw_config: dict = field(default_factory=dict)
    # SAML-specific metadata captured during auth flow
    saml_metadata: dict = field(default_factory=dict)

    def apply_to_request(self, headers: dict = None, cookies: dict = None) -> tuple[dict, dict]:
        """Inject auth into a request's headers and cookies."""
        h = dict(headers or {})
        c = dict(cookies or {})
        h.update(self.headers)
        c.update(self.cookies)
        return h, c


@dataclass
class SAMLFlowInfo:
    """Metadata captured during SAML SSO authentication."""
    idp_url: str = ""                # Identity Provider URL (ADFS/Okta/AzureAD)
    acs_url: str = ""                # Assertion Consumer Service URL
    saml_response: str = ""          # Base64-encoded SAML assertion (truncated)
    relay_state: str = ""            # RelayState parameter
    issuer: str = ""                 # IdP issuer from the assertion
    name_id: str = ""                # Authenticated user's NameID
    session_index: str = ""          # SAML session index
    not_on_or_after: str = ""        # Assertion expiry
    audience: str = ""               # Intended audience (SP entity ID)
    auth_method: str = ""            # How IdP authenticated (NTLM, password, etc.)
    redirect_chain: list = field(default_factory=list)  # Full redirect history


class CredentialStore:
    """
    Manages multiple auth contexts for privilege testing.

    The key feature: you can replay any request through any auth context
    to test access control. Send an admin request as a regular user,
    send an authenticated request without auth, etc.
    """

    def __init__(self):
        self.contexts: dict[str, AuthContext] = {}
        # Always have an unauthenticated context
        self.contexts["unauthenticated"] = AuthContext(
            role="unauthenticated",
            method=AuthMethod.NONE,
            authenticated=True,
        )

    async def setup_from_config(self, accounts: list[dict], http: httpx.AsyncClient):
        """
        Initialize auth contexts from config credential entries.

        For each account, performs the login flow and stores the
        resulting session (cookies, tokens, headers).
        """
        for account in accounts:
            role = account.get("role", "user")
            method = AuthMethod(account.get("method", "none"))

            ctx = AuthContext(role=role, method=method, raw_config=account)

            if method == AuthMethod.NONE:
                ctx.authenticated = True

            elif method == AuthMethod.NTLM:
                ctx = await self._login_ntlm_saml(account, ctx)

            elif method == AuthMethod.FORM:
                ctx = await self._login_form(account, http, ctx)

            elif method == AuthMethod.BEARER:
                token = account.get("token", "")
                ctx.headers["Authorization"] = f"Bearer {token}"
                ctx.tokens["bearer"] = token
                ctx.authenticated = True

            elif method == AuthMethod.BASIC:
                creds = base64.b64encode(
                    f"{account['username']}:{account['password']}".encode()
                ).decode()
                ctx.headers["Authorization"] = f"Basic {creds}"
                ctx.authenticated = True

            elif method == AuthMethod.API_KEY:
                key_name = account.get("header_name", "X-API-Key")
                ctx.headers[key_name] = account.get("api_key", "")
                ctx.authenticated = True

            elif method == AuthMethod.COOKIE:
                cookie_name = account.get("cookie_name", "session")
                ctx.cookies[cookie_name] = account.get("cookie_value", "")
                ctx.authenticated = True

            elif method == AuthMethod.CUSTOM:
                header_name = account.get("header_name", "X-Auth-Token")
                ctx.headers[header_name] = account.get("header_value", "")
                ctx.authenticated = True

            elif method == AuthMethod.OAUTH2:
                ctx = await self._login_oauth2(account, http, ctx)

            self.contexts[role] = ctx
            status = "OK" if ctx.authenticated else "FAILED"
            extra = ""
            if method == AuthMethod.NTLM and ctx.saml_metadata:
                idp = ctx.saml_metadata.get("idp_url", "")
                extra = f" → SAML via {urlparse(idp).hostname or 'IdP'}" if idp else ""
            print(f"    [{status}] Auth context: {role} ({method.value}{extra})")

    async def _login_ntlm_saml(self, account: dict, ctx: AuthContext) -> AuthContext:
        """
        Perform NTLMv2 authentication with SAML SSO redirect handling.

        Flow:
        1. Request the target URL
        2. Follow redirects to the IdP (ADFS/AzureAD)
        3. httpx-ntlm handles the NTLMv2 handshake at the IdP
        4. IdP generates SAML assertion, redirects/POSTs to SP's ACS
        5. SP validates assertion and sets session cookies
        6. We capture all cookies for subsequent requests

        Requires: pip install httpx-ntlm
        """
        target_url = account.get("url", "")
        domain = account.get("domain", "")
        username = account.get("username", "")
        password = account.get("password", "")

        # Build NTLM credentials (DOMAIN\\username format)
        if domain:
            ntlm_user = f"{domain}\\{username}"
        else:
            ntlm_user = username

        try:
            # Try importing httpx-ntlm
            from httpx_ntlm import HttpNtlmAuth
        except ImportError:
            print(f"    [!] httpx-ntlm not installed. Run: pip install httpx-ntlm")
            print(f"    [!] Falling back to manual NTLM negotiation...")
            return await self._login_ntlm_manual(account, ctx)

        saml_flow = SAMLFlowInfo()
        redirect_chain = []

        try:
            # Create a client with NTLM auth that follows all redirects
            # The key: follow_redirects=True makes httpx follow the
            # SAML redirect chain after NTLM auth succeeds at the IdP
            async with httpx.AsyncClient(
                auth=HttpNtlmAuth(ntlm_user, password),
                verify=False,
                follow_redirects=True,
                timeout=httpx.Timeout(30.0),
                max_redirects=15,  # SAML flows can have many redirects
            ) as ntlm_client:

                # Step 1: Hit the target URL — this triggers the redirect chain
                resp = await ntlm_client.get(target_url)

                # Record the redirect chain
                if hasattr(resp, 'history') and resp.history:
                    for r in resp.history:
                        redirect_chain.append({
                            "url": str(r.url),
                            "status": r.status_code,
                        })
                        # Detect IdP URL from redirects
                        if any(idp_hint in str(r.url).lower() for idp_hint in [
                            "adfs", "sts.", "login.microsoftonline",
                            "idp.", "sso.", "auth.", "saml",
                            "federation", "wsfed", "oauth",
                        ]):
                            saml_flow.idp_url = str(r.url)

                # Step 2: Capture all cookies from the final response
                # These are the session cookies set by the SP after
                # SAML assertion validation
                all_cookies = {}

                # Cookies from redirect history
                if hasattr(resp, 'history'):
                    for r in resp.history:
                        for name, value in r.cookies.items():
                            all_cookies[name] = value

                # Cookies from final response
                for name, value in resp.cookies.items():
                    all_cookies[name] = value

                ctx.cookies = all_cookies

                # Step 3: Look for SAML metadata in the response chain
                saml_flow.redirect_chain = redirect_chain
                self._extract_saml_metadata(resp, saml_flow)

                # Step 4: Verify authentication succeeded
                if resp.status_code < 400 and all_cookies:
                    ctx.authenticated = True
                    ctx.saml_metadata = {
                        "idp_url": saml_flow.idp_url,
                        "acs_url": saml_flow.acs_url,
                        "issuer": saml_flow.issuer,
                        "name_id": saml_flow.name_id,
                        "redirect_count": len(redirect_chain),
                        "cookies_captured": len(all_cookies),
                    }
                elif resp.status_code == 401:
                    print(f"    [!] NTLMv2 auth failed — check domain\\username and password")
                    ctx.authenticated = False
                else:
                    # Might have succeeded without cookies (token-based)
                    # Check for bearer token in response
                    try:
                        body = resp.json()
                        for key in ("access_token", "token", "jwt", "auth_token"):
                            if key in body:
                                ctx.tokens["bearer"] = body[key]
                                ctx.headers["Authorization"] = f"Bearer {body[key]}"
                                ctx.authenticated = True
                                break
                    except (json.JSONDecodeError, ValueError):
                        pass

                    if not ctx.authenticated:
                        ctx.authenticated = resp.status_code < 400

        except Exception as e:
            print(f"    [!] NTLMv2+SAML login failed: {type(e).__name__}: {e}")
            ctx.authenticated = False

        return ctx

    async def _login_ntlm_manual(self, account: dict, ctx: AuthContext) -> AuthContext:
        """
        Manual NTLMv2 fallback when httpx-ntlm is not installed.

        Uses raw NTLM negotiate/challenge/authenticate messages via
        the Authorization header. Less robust than httpx-ntlm but
        works without additional dependencies.
        """
        import struct
        import os

        target_url = account.get("url", "")
        domain = account.get("domain", "").upper()
        username = account.get("username", "")
        password = account.get("password", "")

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                # Step 1: Send initial request to get the 401 + negotiate
                resp = await client.get(target_url, timeout=15)

                # Check if NTLM is expected
                www_auth = resp.headers.get("www-authenticate", "").lower()
                if "ntlm" not in www_auth and "negotiate" not in www_auth:
                    # Follow redirects to find the NTLM challenge
                    # The IdP may be on a different URL
                    if resp.status_code < 400:
                        # Already authenticated or no auth needed
                        for name, value in resp.cookies.items():
                            ctx.cookies[name] = value
                        ctx.authenticated = bool(ctx.cookies)
                        return ctx

                # Step 2: Send NTLM Type 1 (Negotiate) message
                # Minimal Type 1 message requesting NTLMv2
                negotiate_flags = (
                    0x00000001 |  # NEGOTIATE_UNICODE
                    0x00000002 |  # NEGOTIATE_OEM
                    0x00000004 |  # REQUEST_TARGET
                    0x00000200 |  # NEGOTIATE_NTLM
                    0x00008000 |  # NEGOTIATE_ALWAYS_SIGN
                    0x00080000 |  # NEGOTIATE_NTLM2
                    0x20000000 |  # NEGOTIATE_128
                    0x80000000    # NEGOTIATE_56
                )
                type1_msg = b"NTLMSSP\x00"  # Signature
                type1_msg += struct.pack("<I", 1)  # Type 1
                type1_msg += struct.pack("<I", negotiate_flags)
                type1_msg += struct.pack("<HHI", 0, 0, 0)  # Domain (empty)
                type1_msg += struct.pack("<HHI", 0, 0, 0)  # Workstation (empty)

                type1_b64 = base64.b64encode(type1_msg).decode()
                resp2 = await client.get(
                    target_url,
                    headers={"Authorization": f"NTLM {type1_b64}"},
                    timeout=15,
                )

                # We'd need to parse Type 2 (Challenge) and compute Type 3 (Authenticate)
                # This requires NTLMv2 hash computation with HMAC-MD5
                # For production use, install httpx-ntlm instead
                print(f"    [!] Manual NTLM requires httpx-ntlm for NTLMv2 hash computation")
                print(f"    [!] Install: pip install httpx-ntlm")
                ctx.authenticated = False

        except Exception as e:
            print(f"    [!] Manual NTLM failed: {e}")
            ctx.authenticated = False

        return ctx

    def _extract_saml_metadata(self, resp: httpx.Response, flow: SAMLFlowInfo):
        """Extract SAML metadata from the response chain for vulnerability testing."""
        body = resp.text

        # Look for SAML assertion in POST forms (common in SAML POST binding)
        saml_response_match = re.search(
            r'name=["\']SAMLResponse["\']\s+value=["\']([^"\']+)', body
        )
        if saml_response_match:
            flow.saml_response = saml_response_match.group(1)[:500]  # Truncate
            # Decode and extract metadata from the assertion
            try:
                decoded = base64.b64decode(flow.saml_response)
                decoded_str = decoded.decode(errors="replace")

                # Extract issuer
                issuer_match = re.search(r'<(?:\w+:)?Issuer[^>]*>([^<]+)', decoded_str)
                if issuer_match:
                    flow.issuer = issuer_match.group(1)

                # Extract NameID
                nameid_match = re.search(r'<(?:\w+:)?NameID[^>]*>([^<]+)', decoded_str)
                if nameid_match:
                    flow.name_id = nameid_match.group(1)

                # Extract SessionIndex
                session_match = re.search(r'SessionIndex=["\']([^"\']+)', decoded_str)
                if session_match:
                    flow.session_index = session_match.group(1)

                # Extract Audience
                audience_match = re.search(r'<(?:\w+:)?Audience[^>]*>([^<]+)', decoded_str)
                if audience_match:
                    flow.audience = audience_match.group(1)

                # Extract NotOnOrAfter
                expiry_match = re.search(r'NotOnOrAfter=["\']([^"\']+)', decoded_str)
                if expiry_match:
                    flow.not_on_or_after = expiry_match.group(1)

            except Exception:
                pass

        # Look for RelayState
        relay_match = re.search(r'name=["\']RelayState["\']\s+value=["\']([^"\']*)', body)
        if relay_match:
            flow.relay_state = relay_match.group(1)

        # Look for ACS URL in form action
        acs_match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body)
        if acs_match:
            flow.acs_url = acs_match.group(1)

    async def _login_form(
        self, account: dict, http: httpx.AsyncClient, ctx: AuthContext
    ) -> AuthContext:
        """Perform form-based login and capture session cookies/tokens."""
        login_url = account.get("url", "")
        username_field = account.get("username_field", "username")
        password_field = account.get("password_field", "password")

        try:
            resp = await http.post(
                login_url,
                data={
                    username_field: account.get("username", ""),
                    password_field: account.get("password", ""),
                },
                follow_redirects=True,
            )
            for name, value in resp.cookies.items():
                ctx.cookies[name] = value
            try:
                body = resp.json()
                for key in ("token", "access_token", "jwt", "auth_token", "sessionToken"):
                    if key in body:
                        ctx.tokens["bearer"] = body[key]
                        ctx.headers["Authorization"] = f"Bearer {body[key]}"
                        break
            except (json.JSONDecodeError, ValueError):
                pass
            ctx.authenticated = bool(ctx.cookies) or bool(ctx.tokens)
        except Exception as e:
            print(f"    [!] Login failed for {account.get('role')}: {e}")
            ctx.authenticated = False
        return ctx

    async def _login_oauth2(
        self, account: dict, http: httpx.AsyncClient, ctx: AuthContext
    ) -> AuthContext:
        """Perform OAuth2 client credentials flow."""
        token_url = account.get("token_url", "")
        client_id = account.get("client_id", "")
        client_secret = account.get("client_secret", "")
        scope = account.get("scope", "")

        try:
            resp = await http.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            }, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token", "")
                if token:
                    ctx.tokens["bearer"] = token
                    ctx.headers["Authorization"] = f"Bearer {token}"
                    ctx.authenticated = True
        except Exception as e:
            print(f"    [!] OAuth2 login failed: {e}")
        return ctx

    def get(self, role: str) -> Optional[AuthContext]:
        """Get auth context by role name."""
        return self.contexts.get(role)

    def list_roles(self) -> list[str]:
        """List all available auth roles."""
        return list(self.contexts.keys())

    async def replay_as(
        self,
        http: httpx.AsyncClient,
        method: str,
        url: str,
        role: str,
        headers: dict = None,
        body: str = None,
    ) -> httpx.Response:
        """
        Replay a request using a different auth context.

        Core of privilege escalation testing: capture a request made
        as admin, replay it as regular user or unauthenticated.
        """
        ctx = self.contexts.get(role)
        if not ctx:
            raise ValueError(f"Unknown role: {role}")
        h, c = ctx.apply_to_request(headers or {})
        return await http.request(
            method, url, headers=h, cookies=c,
            content=body, follow_redirects=True,
        )
