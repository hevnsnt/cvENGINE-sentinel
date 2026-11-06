"""The in-process network probes a Sentinel runs for cvENGINE, and the pure readers they share with it.

Every probe kind carries a scope policy (``policy.ScopePolicy``, from ``target['scope']``) that cvENGINE computed when it built the task: the
names and addresses the task may touch, what is excluded, and whether private space is allowed. The policy is asked at every hop (the first
request, every redirect, every script a page loads, every follow-up) on top of this Sentinel's own floor (``cvengine_scanner.scope``), and the
hosts actually asked are reported back.

- ``policy``, ``names``: the scope policy and the host name helpers it uses;
- ``transport``, ``egress_proxy``, ``legacy_tls``, ``http``: resolve once and connect only to vetted numeric addresses, optionally through
  this Sentinel's own probe proxy;
- ``version_probes``: the version and identity probes (the ``http_probe`` kind);
- ``dns``: name resolution (the ``dns_resolve`` kind);
- ``alive``: whether a retired name's last known addresses still answer (the ``alive_check`` kind);
- ``buckets``: anonymous checks of cloud storage buckets (the ``bucket_check`` kind);
- ``routes``: how a host's web routes answer an anonymous request, and the sign-in state they show (the ``route_probe`` kind);
- ``versions``, ``fingerprint``, ``cms``, ``wp_core``, ``js_libraries``, ``soft404``, ``sensitive``: the pure readers of what a host answered,
  shared with cvENGINE.

The modules are copied from cvENGINE's ``cveFeed`` package; anything that reads cvENGINE's database stays there.
"""
