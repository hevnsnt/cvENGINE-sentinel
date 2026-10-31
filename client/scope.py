"""The Sentinel's scope floor lives in ``cvengine_scanner.scope`` (the cvENGINE server shares it); this module is that module under its old
name, so ``client.scope`` and ``cvengine_scanner.scope`` are one object and a name patched on either is seen by both. It also tells the
library where this machine's own network setting is (``client.config``), which is what makes an internal Sentinel internal."""
import sys

from cvengine_scanner import scope as _scope

from . import config

_scope.use_internal_setting(lambda: config.is_internal())

sys.modules[__name__] = _scope
