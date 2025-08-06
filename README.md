vuln_scan_suite
===============

Simple suite for cybersecurity scanning.

It has 4 tools.

- Attack surface recognition.
- Enumeration of services and vulnerabilities.
- Tool to find basic XSS vulnerabilities.
- Tool to find basic SQLi vulnerabilities.

Note: XSS tool for dynamic pages and SQLi tool are using selenium with chrome browser to perform their actions. Therefore, you need chrome browser updated to latest to use it.

Usage.
-----

Install the requirements listed on requirements.txt
```
pip install requirements.txt
```
Then Run the menu:
```
python run_suite.py
```
