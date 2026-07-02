"""Step-up verification endpoints (challenge info / initiate / complete).

The client cycle documented in flows-and-verification.md §2: a protected
endpoint answers 403 with a ``verification`` envelope → the client drives
one of the offered factors through these endpoints → retries the original
request (the grant is stored server-side; stateless clients resend the
returned ``X-Verification-Token``).
"""
