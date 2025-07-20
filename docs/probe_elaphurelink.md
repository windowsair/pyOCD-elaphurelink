---
title: elaphureLink probe
---

The elaphureLink backend for pyOCD.

## Install

Install from pip:
```bash
python3 -mpip install -U pyocd-elaphurelink
```

The latest pyocd-elaphurelink package is available [on PyPI](https://pypi.org/project/pyocd-elaphurelink/).

You can also install directly from the source by cloning the git repository and running:

```
$ python3 pip install .
```

## Quick start

Set `cmsis_dap.elaphurelink.addr` session option, and use `list command`:

```bash
$ pyocd list -O "cmsis_dap.elaphurelink.addr=dap.local"
  #   Probe/Board   Unique ID          Target
-----------------------------------------------
  0                                    n/a
      windowsair    ESP wireless DAP
```

## Session Option

`cmsis_dap.elaphurelink.addr`: Device address of elaphureLink
