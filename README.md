# ABScanner

### AltraBits Network Scanner

### Release Note

##### Version 1.0

This commit releases the first version of ABScanner as a network tool scanner for AltraBits devices. 
Currently tested only in Windows 11.

### Run from command line

Create a virtual environment and install `psutil` needed to detect all network interfaces.

```shell
python3.13 -m venv venv
source venv/bin/activate
pip install psutil
```

Run the Python `main.py` GUI application.

```shell
python3.13 main.py
```

#### MacOS (Python installed via Homebrew)

On macOS, \_tkinter is not bundled by default with Python interpreter via Homebrew.

To install \_tkinter manually, run:

```shell
brew install tcl-tk
```

Or, try reinstalling the Python interpreter from Homebrew with Tk support enabled.

```shell
brew reinstall python-tk@3.13
```

Lunch ABScanner from command line:

```shell
python3.13 main.py
```

Or build a MacOS compatible app.

```shell
source venv/bin/activate
pip install pyinstaller
pip install pillow
pyinstaller --onefile --name "ABScanner" --noconsole --icon=ab_cobalt.ico --add-data "ab_cobalt.png:." main.py
```

### Windows (.exe)

Generate a single-file executable for Windows using PyInstaller.



```shell
pyinstaller --onefile --name "ABScanner" --noconsole --icon=ab_cobalt.ico --add-data "ab_cobalt.png;." main.py
```