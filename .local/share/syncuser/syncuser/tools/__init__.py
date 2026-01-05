# syncuser/tools/__init__.py
from __future__ import annotations

from . import ssh as ssh
from . import identity as identity
from . import log_utils as log_utils
from . import misc as misc
from . import blacklist as blacklist

# Back-compat shims (old code may import these directly from .tools)
# Prefer: from .tools import log_utils; log_utils.supports_color(...)
supports_color = log_utils.supports_color
colorize = log_utils.colorize
kv_lines = log_utils.kv_lines
