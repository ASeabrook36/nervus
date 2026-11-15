"""nervus, the MCP bastion (ADR-0001).

`__version__` is its release number (ADR-0029 question 2a). The number is
written in one place, `pyproject.toml`'s [project] version, and read here from
the installed package's metadata, which hatchling, the tool that builds the
package for pip to install, wrote from it. With no nervus installed where
Python finds packages, it is "unknown", as a backup's manifest then says.
Otherwise it is the number that install was built with, which an editable
install, one that runs the tree's own code in place, keeps until it is
installed again.
"""

import importlib.metadata as _metadata

try:
    __version__ = _metadata.version("nervus")
except _metadata.PackageNotFoundError:
    __version__ = "unknown"
