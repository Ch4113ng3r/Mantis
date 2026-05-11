"""
Comprehensive vulnerability scanner modules.

Each module groups scanners by vulnerability family:
- injection.py: SSTI, blind SQLi, command injection, path traversal, XPath, LDAP, NoSQL, prototype pollution, HPP, CRLF
- client_side.py: DOM clobbering, CSS injection, postMessage, dangling markup, JSONP hijacking, client-side template injection, web storage
- auth_session.py: JWT (alg:none, alg confusion, kid traversal, JKU/X5U), session puzzling, cookie tossing, token leakage, account pre-registration
- http_protocol.py: HPP, verb tampering, H2C smuggling, WebSocket smuggling, Content-Type confusion, HTTP method override
- server_processing.py: PDF SSRF, ImageTragick, ZipSlip, CSV injection, server-side PDF manipulation
- cryptographic.py: Weak RNG, padding oracle, broken crypto, timing attacks
- business_logic.py: Negative quantity, rounding, coupon stacking, free shipping bypass, gift card abuse, referral abuse, MFA downgrade, account merging
- infrastructure.py: Exposed .git/.svn/.env, debug endpoints, source maps, API versioning bypass, ReDoS, exposed Swagger
- modern_protocols.py: gRPC reflection, SSE injection, GraphQL introspection/depth/batch
- standard.py: Reflected/stored XSS, error-based SQLi, CORS, CSRF, open redirect, host header, file upload, clickjacking
- chained.py: Second-order injection, password reset poisoning, OAuth token theft chains
"""
