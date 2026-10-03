"""Repository-wide pytest configuration.

The test suite exercises development-only behaviour (the public development
HMAC secret, per-process replay state) on purpose, so it declares explicit
test intent here rather than depending on a developer's shell or CI's
environment. Tests that check production behaviour set ACTENON_ENV
themselves (monkeypatch), which overrides this default.
"""

import os

os.environ["ACTENON_ENV"] = "test"
