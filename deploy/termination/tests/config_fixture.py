#!/usr/bin/env python3
"""PUBLIC renderer contract consumed by the actual Rust Config test; no I/O."""
import json
from test_render import fixture, renderer
print(json.dumps(renderer.workload(fixture())))
