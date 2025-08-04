# Running Tests

The tests are designed to be run on non-Raspi hardware.

## Setup
On your testing machine you'll have to install:
```bash
# general dependencies
pip3 install -r requirements.txt

# test suite dependencies
pip3 install -r tests/requirements.txt
```

Then make the `seedsigner` python module visible/importable to the tests by installing it:
```
pip3 install -e .
```

## Running all tests, calculating overall test coverage
tldr: just run the convenience script from the project root:

```bash
./tests/run_full_coverage.sh
```

## Running tests manually
Run the whole test suite:
```
pytest
```

Run a specific test file:
```
pytest tests/test_this_file.py
```

Run a specific test:
```
pytest tests/test_this_file.py::test_this_specific_test
```

Force pytest to show logging output:
```bash
pytest tests/test_this_file.py::test_this_specific_test -o log_cli=1

# or (same result)

pytest tests/test_this_file.py::test_this_specific_test --log-cli-level=DEBUG
```

Annoying complications:
* If you want to see `print()` statements that are in a test file, add `-s`
* Better idea: use a proper logger in the test file and use one of the above options to display logs

## JavaCard integration tests

End-to-end tests for a physical JavaCard are provided in
`tests/test_javacard_workflow.py`. These tests require a blank, compatible
JavaCard, the [Satochip-DIY](https://github.com/3rdIteration/Satochip-DIY)
toolchain with Java and `ant`, and the Python packages `pysatochip` and
`pyscard`. The tests are skipped by default; set `RUN_JAVACARD_TESTS=1` to
enable them. Running these tests will erase any applets currently installed on
the card.

1. Clone the Satochip-DIY repository and build the CAP files:

    ```bash
    git clone https://github.com/3rdIteration/Satochip-DIY.git
    cd Satochip-DIY
    ant
    ```

2. Install the Python dependencies:

    ```bash
    pip install pysatochip pyscard
    ```

3. Connect a blank JavaCard to the system.

4. From the SeedSigner project root run:

    ```bash
    export SATOCHIP_DIY_PATH=/path/to/Satochip-DIY
    RUN_JAVACARD_TESTS=1 pytest tests/test_javacard_workflow.py
    ```

The test installs the Satochip applet, signs a message and a PSBT to verify
signing functionality, uninstalls it, then installs the Seedkeeper applet to
exercise card management features (label update, PIN change, NFC policy)
and to import, export, and remove each supported secret type before removing
the applet.

## Screenshot generator
The screenshot generator is meant to mostly be a utility and not really part of the test suite. However,
it is actually implemented to be run by `pytest`.

see: [Screenshot generator README](screenshot_generator/README.md)

## Generate coverage manually
Run tests and generate test coverage
```bash
coverage run -m pytest
```

The screenshots can generate their own separate coverage report:
```bash
coverage run -m pytest tests/screenshot_generator/generator.py --locale es
```

Show the resulting test coverage details:
```bash
coverage report
```

Generate the interactive html report:
```bash
coverage html
```
