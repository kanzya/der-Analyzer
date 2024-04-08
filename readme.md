# der-Analyzer

Output pem in json format.

**Only pilot features are implemented**

## how to use

### nomal version
```python
from der_Analyzer import PEM_analyzer
print(PEM_analyzer(hex).import_pem(open("./test/4096.pem").read()))
```

### collapted version

Parse the value with "*" for the unknown part
**Only works if the broken part of the PEM does not affect the HEADER**


```python
from der_Analyzer import PEM_analyzer
print(PEM_analyzer(hex).import_pem(open("./test/some_broken.pem").read()))
```

# Copyright
This library is distributed under Apache 2.0 License. See LICENSE.

(C) 2023 kanon

https://github.com/kanzya/der-Analyzer

For redistribution, just say that it has been changed and note the link for our files.

