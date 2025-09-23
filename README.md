# ABScanner

### AltraBits Network Scanner

### Release Note

##### Version 1.0

This commit releases the first version of ABScanner as a network tool scanner for AltraBits devices. 
Currently tested only in Windows 11.

### Windows (.exe)

Generate a single-file executable for Windows using PyInstaller.

```shell
 pyinstaller --onefile --name "ABScanner" --noconsole --icon=ab_cobalt.ico --add-data "ab_cobalt.png;." main.py
```