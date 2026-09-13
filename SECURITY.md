# Security

## Reporting a vulnerability

Mail c.schlueter@acidnetworks.net, or open a private advisory through GitHub's
[Report a vulnerability](https://github.com/AcidDemon/scrip/security/advisories/new)
form. Please do not open a public issue for anything exploitable.

Include what you need to reproduce it: version or commit, the config that was
running, and the request or paste that triggers it. Expect a first reply within
a week.

## Scope

scrip is alpha and self-hosted. Reports should cover the code and its behavior
on an operator's server. In scope:

- reading, deleting, or overwriting a paste without its URL, delete token, or
  shell access to the server
- getting past the rate limits, connection caps, paste quota, or ban list
- turning a paste into code execution in a reader's browser, or into anything
  the server executes
- recovering plaintext that a takedown, a burn-after-read, or an expiry was
  supposed to have removed from disk
- anything that makes `encrypt_at_rest` weaker than its stated bound: at rest
  only, keyed by the URL, with size, timestamps, and author IP left in the
  clear

These documented behaviors are out of scope:

- the server holding plaintext in flight, and deriving the key from the URL on
  every read, under `encrypt_at_rest`
- a reverse proxy's access log recording the URL, which under encryption is
  the key
- anything reachable only with shell access to the host or read access to the
  database file
- `X-Forwarded-For` being trusted from loopback: that is the documented
  contract with a local proxy, and it is what the deployment docs require

## Deployment

`deploy/` carries a hardened systemd unit, an nftables ruleset, and the
operational notes. Running scrip without a reverse proxy in front, or with a
non-local one, breaks the assumption every per-source control rests on.
