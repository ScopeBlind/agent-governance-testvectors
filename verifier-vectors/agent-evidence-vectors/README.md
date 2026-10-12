# agent-evidence-vectors receipt-signature corpus

CI replays the `vectors-receipt-signature` corpus of [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) 0.17.4 (25 vectors for draft-farley-acta-signed-receipts: refusals with their failure codes, acceptances, and key-window cases) through the same `@veritasacta/verify@0.10.23` that `../run.mjs` pins.

```bash
python -m pip install --require-hashes -r verifier-vectors/agent-evidence-vectors/requirements.txt
npm install --prefix /tmp/verify --no-save @veritasacta/verify@0.10.23
PATH="/tmp/verify/node_modules/.bin:$PATH" ./verifier-vectors/agent-evidence-vectors/run.sh
```

The corpus is installed from PyPI by wheel hash and never copied here. Before the replay, `run.sh` fetches the release's `CORPUS-DIGESTS.txt`, checks its signature with cosign against the release's `cosign.pub`, and `check_digest.py` confirms the installed corpus carries the signed digest and vector count. `adapter.py` maps the verifier's JSON onto the corpus contract (`valid`, `invalid` with a code, `undecidable`) and replays a receipt's chain context where the vector supplies one.

Exit status: 0 every vector reached its expected outcome, non-zero otherwise. The report lands in `receipts/agent-evidence-vectors-report.json`, which the workflow uploads with the other receipts. To move the pin, change the version and hash in `requirements.txt` and `release` in `run.sh` together.
