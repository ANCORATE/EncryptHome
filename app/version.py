# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin
"""Release identity without Qt imports — safe for ``main.py --version``."""

from version import VERSION as version, VERSION_YEAR as version_year

edition = "EncryptHome"  # Edition der Software
type_edition = "Capsule"
