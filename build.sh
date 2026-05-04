#!/usr/bin/env bash
set -e

uv build
python3.13 -m pip install --force-reinstall dist/mcp_postgres_toolkit-0.1.0-py3-none-any.whl
