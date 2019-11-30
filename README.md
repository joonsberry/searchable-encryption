# Searchable Encrytion

_Data Security and Privacy Project 3_
_Collaborators: Jonathan Kenney and Brennan Thomas_

## Setup

Install a [stable version](https://www.python.org/downloads/) of Python 3.6+

Use pip to install the `cryptography` package

```
pip3 install cryptography
```

## Execution

First, create desired input files. These files should be located in the data/files folder and follow the naming convention `f#.txt` where `#` is a positive integer greater than 0.

From **TOP DIRECTORY**, run in following order:

### keygen.py
```
python3 build/keygen.py 32
```
_NOTE: key size parameter can be 16, 24, or 32_

### enc.py
```
python3 build/enc.py
```

### tokengen.py
```
python3 build/tokengen.py [KEYWORD]
```
_NOTE: select keyword from various input files, punctuation is stripped_

### search.py
```
python3 build/search.py
```

Search results will be in `data/result.txt`