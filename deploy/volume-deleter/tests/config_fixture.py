#!/usr/bin/env python3
"""Public renderer contract fixture consumed by the actual Rust Config test."""
import json
from test_render import fixture, renderer
print(json.dumps(renderer.workload(fixture())))
