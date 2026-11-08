"""The Sentinel's scope floor lives in ``cvengine_scanner.scope`` (the cvENGINE server shares it); this module is that module under its old
name, so ``client.scope`` and ``cvengine_scanner.scope`` are one object and a name patched on either is seen by both. It also tells the
library where this machine's own network setting is (``client.config``), which is what makes an internal Sentinel internal, and
the private networks the built-in scanner may scan (``config.private_ranges``)."""
import sys

from cvengine_scanner import scope as _scope

from . import config

_scope.use_internal_setting(lambda: config.is_internal())
_scope.use_denied_ranges(config.deny_ranges)  # the operator's own deny list (CVENGINE_SENTINEL_DENY_RANGES): refused before any tool or probe connects
_scope.use_private_ranges(config.private_ranges)  # the built-in scanner's vantage setting; empty on every other Sentinel

sys.modules[__name__] = _scope
