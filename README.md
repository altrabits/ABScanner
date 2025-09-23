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

#### MacOS 

On macOS, \_tkinter isn’t bundled by default if you installed Python via Homebrew.


```
brew install tcl-tk
```

### Windows (.exe)

Generate a single-file executable for Windows using PyInstaller.

```shell
 pyinstaller --onefile --name "ABScanner" --noconsole --icon=ab_cobalt.ico --add-data "ab_cobalt.png;." main.py
```