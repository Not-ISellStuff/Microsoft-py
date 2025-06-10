# Microsoft-py
Library made for checking whether a Microsoft is valid or not.

# Features

```
Login | Logs in account and returns a tuple (status, response)
AccessToken | Returns access token using response of type requests.Response
Capture | Returns credit card information in json format
Proxy Support
```

# Usage

```
from microsoft import Microsoft

checker = Microsoft()

# ------------------------------------------ #

email = "lidianemarquesdemelo@hotmail.com"
password = "Lidi142031@"
proxy = None

# ------------------------------------------ #

status, response = checker.Auth(email, password, proxy)
capture = checker.Capture(response, proxy)

if status == "ok":
  print("Credit Card Info: \n{capture}")
```
