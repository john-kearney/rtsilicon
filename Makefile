# rtsilicon Makefile — the contributor's entry point.
#
# Usage:
#   make secure          # scan current dir, emit attestation + badge
#   make secure-ci       # same, but exit 1 on candidates (CI mode)
#   make secure-target T=/path/to/rtl   # scan a specific target
#   make test            # run the test suite
#   make install         # pip install -e . into the local venv

.PHONY: secure secure-ci secure-target test install lint help

RT_SI ?= .venv/bin/rt-si

help:
	@echo "rtsilicon — hardware security attestation for OSS HW contributors"
	@echo ""
	@echo "Targets:"
	@echo "  make secure            Scan current directory, emit attestation + badge"
	@echo "  make secure-ci         Same, but exit 1 if candidates found (for CI)"
	@echo "  make secure-target T=X Scan target directory X"
	@echo "  make test              Run the test suite"
	@echo "  make install           Install rt-si into .venv"
	@echo ""
	@echo "The attestation is written to attestation.json and printed to stdout."
	@echo "Badge is suitable for embedding in a README."

# The default security check — scans the current directory.
secure:
	$(RT_SI) attest --target . --output attestation.json

# CI mode — fails the build if candidates are found.
secure-ci:
	$(RT_SI) attest --target . --output attestation.json --ci --no-badge

# Scan a specific target.
secure-target:
	@test -n "$(T)" || (echo "Usage: make secure-target T=/path/to/rtl" && exit 1)
	$(RT_SI) attest --target "$(T)" --output attestation.json

test:
	.venv/bin/python -m pytest tests/ -v

install:
	python3 -m venv .venv
	.venv/bin/pip install -e .

lint:
	.venv/bin/python -m ruff check src/ tests/
