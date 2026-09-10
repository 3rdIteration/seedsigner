# Desktop Simulation Mode

SeedSigner can run on a standard PC for development and testing. This mode uses your
computer's display and camera and is **not** intended for handling real
seeds or private keys.

## Installation

1. Install the Python requirements:
   ```bash
   python -m pip install --no-deps -r requirements.txt
   python -m pip install --no-deps -r requirements-desktop.txt
   ```
2. Run the application:
   ```bash
   python src/main.py
   ```

On start-up a warning splash screen reminds you that desktop mode is for
testing only.

### QR scanning (pyzbar) on Windows

QR scanning needs [pyzbar](https://pypi.org/project/pyzbar/), which wraps the
native ZBar library. `requirements.txt` pins our
[pyzbar fork](https://github.com/seedsigner/pyzbar) (commit `c3c2378`), whose
`decode()` supports the `binary=` keyword argument used for binary QR formats
such as SeedQR.

On Linux you also install the native library (`sudo apt install libzbar0`).
On Windows there is no equivalent package-manager step: the fork ships only
source, so after installing the requirements you must supply ZBar's DLLs
yourself. The official PyPI `pyzbar` wheel bundles them; copy the two DLLs
out of it into the installed fork's package directory:

```powershell
# 1. Download and unpack the official Windows wheel (64-bit Python)
python -m pip download pyzbar==0.1.9 --only-binary=:all: -d %TEMP%\pyzbar_dl
python -m zipfile -e %TEMP%\pyzbar_dl\pyzbar-0.1.9-py2.py3-none-win_amd64.whl %TEMP%\pyzbar_dl

# 2. Copy the ZBar DLLs into the installed fork package
$pkg = python -c "import pyzbar, os; print(os.path.dirname(pyzbar.__file__))"
Copy-Item "%TEMP%\pyzbar_dl\pyzbar\libiconv.dll", "%TEMP%\pyzbar_dl\pyzbar\libzbar-64.dll" $pkg

# 3. Verify (both checks must succeed)
python -c "from pyzbar import pyzbar; print('pyzbar_ok')"
python -c "import inspect; from pyzbar import pyzbar; assert 'binary' in inspect.signature(pyzbar.decode).parameters; print('fork_ok')"
```

The fork's `zbar_library.py` loads `libzbar-64.dll` (and its dependency
`libiconv.dll`) from the package directory on 64-bit Windows. Without them,
importing pyzbar fails with `FileNotFoundError: Could not find module
'libiconv.dll'`, and QR scanning is disabled at run time
(`DecodeQR.is_qr_scanner_available()` returns False).

The same two DLLs work for any Python version; re-copy them if you ever
reinstall pyzbar into a fresh environment.

## Controls

The Waveshare HAT's physical buttons are mapped to your keyboard:

| Hardware button | Keyboard key |
|-----------------|--------------|
| Up              | Up Arrow     |
| Down            | Down Arrow   |
| Left            | Left Arrow   |
| Right           | Right Arrow  |
| Center          | Enter/Return |
| Key 1           | `1`          |
| Key 2           | `2`          |
| Key 3           | `3`          |

A row of clickable on‑screen buttons is also displayed beneath the
simulated screen. Clicking these buttons is equivalent to pressing the
associated keys.

## Camera selection

Desktop mode can use any camera recognised by your operating system. The
active device can be selected from the **Settings → Hardware** menu,
which presents a drop-down list of the detected cameras by name.

The display can simulate either a 240×240 or 320×240 screen. Choose the
desired size from **Settings → Hardware → Display type**.
