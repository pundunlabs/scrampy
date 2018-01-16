# Scrampy

Scram authentication in Python

**Usage**

```python
import scrampy

# Pass a socket connection instance with TLSv1, username and password.
connection = scrampy.initialize(host, port)
scrampy.authenticate(connection, username, password)
```
