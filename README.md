# Context Aware Password Advisor

A local encrypted password vault with personal-context assessment, credential relationship checks and save-time warnings. This is a research prototype. The current risk score is a heuristic priority, not a probability of compromise.

## Run locally

Python 3.14 on macOS was used for the recorded verification. Other Python/platform combinations need their own validation.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m streamlit run app.py
```

Existing vault data is opened only when you use the app. No real vault or credentials are needed for tests or research experiments. Credential suggestions are generated locally; no Groq key is needed. HIBP queries send a five-character SHA-1 prefix with padding requested. Failed checks remain unknown.

## Faculty review deliverables

- [Detailed change list and review mapping](docs/REVIEW1_CHANGES.md)
- [Research revision and limitations](docs/RESEARCH_REVISION.md)
- [Experimental protocol and reproduction commands](docs/REVIEW1_PROTOCOL.md)
- [Security test matrix](docs/SECURITY_MATRIX.md)
- [Executed results](results/review1/SUMMARY.md)

## Verify

```sh
.venv/bin/python -m pytest -q
.venv/bin/python scripts/review_experiments.py --profiles 1002 --out results/review1
.venv/bin/python scripts/review_clusters.py
.venv/bin/python scripts/review_performance.py --sizes 10 100 500 1000 5000 --repeats 3
```

The experiment generator creates **synthetic engineering fixtures**, not independent validation data. It does not read the real vault. `requirements-lock.txt` records the tested environment. New evaluation outputs are separate from the existing historical result files, whose provenance has not been established.

The Controlled Study page defaults to demo mode. Human collection additionally requires `STUDY_MODE=1`, `STUDY_ETHICS_REFERENCE` and a prespecified `STUDY_SEED`; these flags record configuration and cannot verify actual institutional approval. Use fictional credentials only. Do not present demo or simulated decisions as human results.
