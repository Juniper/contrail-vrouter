atomic-test
===========

Unit tests for atomic operation functions used in vRouter on Windows.

## Building

Unit tests are build as a dependency of the vRouter itself.
To build them, execute a following command from your Contrail sandbox directory:

```bash
scons vrouter
```

To execute tests run:

```bash
.\build\debug\vrouter\atomic-test\atomic-test.exe
```
