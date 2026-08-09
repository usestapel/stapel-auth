# stapel-auth — contract emission + drift gate (contract-pipeline.md §2-3, ETALON).
#
# This module emits its OWN contract triad (schema.json + flows.json + errors.json)
# per-module, byte-identical to the monolith aggregate's auth slice, from a
# single-module {auth + gdpr + core} Django instance mounted at the canonical
# /auth/api/ prefix (see _codegen.py / _codegen_settings.py / codegen_urls.py),
# PLUS the fourth artifact capabilities.json (capability-config.md §2): config
# axes derived from conf.py DEFAULTS + the urls.py gate registry, merged with
# the hand-curated docs/capabilities.meta.json (see _capabilities.py).
#
# PYTHON must have the module + its deps importable (the workspace venv, or a CI
# venv). The authoritative CI gate is tests/test_contract.py (run under pytest);
# these targets are the dev-loop convenience.
PYTHON ?= python3

.PHONY: contract contract-check

# Emit the contract triad + capabilities.json + llms.txt (the fifth contract
# artifact, stapel_tools.llms_txt) into docs/.
#
# stapel-auth is the one module in the fleet whose llms.txt does not fit the
# generator's default 4000-token budget (~7261 tokens, driven by the 28-axis
# method-gate matrix and the 53-entry error registry — both real surface, not
# padding). The owner's call: raise the ceiling to 8000 for this module only,
# do NOT shorten intent/summary lines in capabilities.meta.json to fit — a
# trimmed-to-fit context file is indistinguishable from a complete one at the
# point of use, which is the failure mode the hard-budget gate exists to
# prevent. This is a deliberate, reviewed exception, not a workaround of the
# gate: contract-check below enforces the same 8000 ceiling, it does not
# disable the check.
#
# README.md is the SIXTH artifact (tracker #257): assembled by
# stapel_tools.readme from docs/readme.md (the human half — what this module
# is, how to think about it) plus everything emitted above. Badges, version,
# surface counts and doc links are generated, so a release cannot leave them
# behind. Edit docs/readme.md; never README.md.
contract:
	$(PYTHON) -m stapel_auth._codegen --out docs
	$(PYTHON) -m stapel_auth._capabilities --out docs
	$(PYTHON) -m stapel_tools.llms_txt . --budget 8000
	$(PYTHON) -m stapel_tools.readme .

# Drift gate: regenerate into a temp dir and diff against the committed docs/*.json
# (mirrors the monolith's `make codegen-check` and the frontend's `gen:*:check`).
contract-check:
	@tmp=$$(mktemp -d); \
	$(PYTHON) -m stapel_auth._codegen --out "$$tmp" || { rm -rf "$$tmp"; exit 1; }; \
	$(PYTHON) -m stapel_auth._capabilities --out "$$tmp" || { rm -rf "$$tmp"; exit 1; }; \
	$(PYTHON) -m stapel_tools.llms_txt . --out "$$tmp" --budget 8000 || { rm -rf "$$tmp"; exit 1; }; \
	rc=0; \
	for f in schema.json flows.json errors.json capabilities.json llms.txt; do \
		if ! diff -q "docs/$$f" "$$tmp/$$f" >/dev/null 2>&1; then \
			echo "DRIFT: docs/$$f is stale — run 'make contract' and commit it"; \
			diff "docs/$$f" "$$tmp/$$f" | head -20; rc=1; \
		fi; \
	done; \
	rm -rf "$$tmp"; \
	$(PYTHON) -m stapel_tools.readme . --check || rc=1; \
	if [ $$rc -eq 0 ]; then echo "contract-check: docs/{schema,flows,errors,capabilities,llms.txt} + README.md up to date"; fi; \
	exit $$rc


.PHONY: migration-lint

# Expand/contract gate for Django migrations (release-management.md §3;
# stapel_tools.migration_lint). Requires stapel-tools importable (the
# workspace venv, or `pip install stapel-tools` once published).
migration-lint:
	$(PYTHON) -m stapel_tools.migration_lint . --strict
