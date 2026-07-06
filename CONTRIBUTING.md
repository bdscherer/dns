# Contributing to FaithFilter

Thanks for helping make FaithFilter better. It's a tool families rely on,
so the bar is correctness and clarity over cleverness.

## Ground rules

- **License**: contributions are accepted under the project's
  [AGPL-3.0](LICENSE). By opening a pull request you agree your work is
  licensed the same way.
- **Security issues** go through [SECURITY.md](SECURITY.md), not public
  issues or PRs.
- Be kind. This project exists to protect people; keep that spirit.

## Development setup

```sh
git clone https://github.com/bdscherer/dns.git
cd dns
pip install -r requirements.txt
python3 test_faithfilter.py     # 65 offline tests, no internet needed
python3 test_gui.py             # GUI helper tests (no display needed)
```

Run the service locally on an unprivileged port:

```sh
python3 faithfilter.py --config test_config.yaml   # DNS on :5353, API on :5001
```

## Before you open a pull request

1. **Add or update tests.** The suites run offline against a fake upstream
   DNS server — please keep them that way (no network in tests).
2. **Run both test files** and make sure they pass.
3. Keep changes focused; match the surrounding code style (standard library
   first, small functions, comments that explain *why*).
4. Update `README.md`, `config.yaml` (the commented reference) and
   `CHANGELOG.md` when you change behavior or add options.
5. Don't commit build artifacts, logs, or secrets (see `.gitignore`).

## Good first contributions

- Additional blocklist source presets in `config.yaml`.
- More search engines in the browser extension.
- Docs and setup guides for specific routers.
- Translations of the block page / dashboard strings.

## Project layout

| Path | What it is |
|---|---|
| `faithfilter.py` | The whole service: resolver, filters, API, e-mail, accountability |
| `faithfilter_gui.py` | The native desktop Control Panel |
| `extension/` | The optional browser extension (Manifest V3) |
| `config.yaml` | Fully commented configuration reference |
| `test_faithfilter.py`, `test_gui.py` | Offline test suites |
