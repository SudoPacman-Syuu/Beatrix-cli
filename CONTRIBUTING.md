# Contributing to Beatrix

Thanks for your interest in contributing. Here's how to get set up and submit changes.

## Dev Setup

```bash
git clone https://github.com/SudoPacman-Syuu/beatrix-cli.git
cd beatrix-cli
make install-dev
```

`make install-dev` installs Beatrix in editable mode so your changes are reflected immediately without reinstalling.

## What to Work On

Check the [Issues](https://github.com/SudoPacman-Syuu/beatrix-cli/issues) tab for open tasks. Issues labeled `good first issue` are a good starting point. Issues labeled `help wanted` are areas where contributions are especially welcome.

## Adding a Scanner Module

1. Create `beatrix/scanners/your_module.py` extending `BaseScanner`
2. Implement the `scan(self, context: ScanContext)` method — return a list of `Finding` objects
3. Register it in `beatrix/core/engine.py`
4. Add a row to the Scanner Modules table in `README.md`

See `beatrix/scanners/cors.py` for a minimal example.

## Submitting a Pull Request

1. Fork the repo and create a branch: `git checkout -b your-feature`
2. Make your changes
3. Run the test suite: `make test`
4. Open a PR against `main` with a clear description of what changed and why

## Reporting Bugs

Open an [Issue](https://github.com/SudoPacman-Syuu/beatrix-cli/issues/new) with:
- Beatrix version (`beatrix --version`)
- The command you ran
- What you expected vs what happened
- Relevant output (redact any sensitive targets)

## False Positives / Scanner Accuracy

If a module is producing false positives or missing findings on a class of target, open an issue with a minimal reproducible example (a public target that demonstrates the problem).
