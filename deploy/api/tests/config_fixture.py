#!/usr/bin/env python3
"""Emit public test-only renderer output for the real Rust Config contract test."""
from test_render import fixture, renderer
import json
print(json.dumps(renderer.render(fixture())))
