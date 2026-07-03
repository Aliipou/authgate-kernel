"""Pytest bootstrap.

Force the pure-Python kernel backend for the test suite so a single Entity/Action
type system is used within the process. When the Rust extension (`authgate_kernel`)
is installed, `authgate.kernel` exports the PyO3 types while several modules import
the pure-Python `authgate.kernel.entities` types — mixing them raises
"Entity cannot be converted to Entity". The Rust TCB is validated separately by the
cargo test / Kani jobs; the Python reference is what the pytest suite exercises.

Set before any `authgate` import so the backend switch in `authgate.kernel.__init__`
sees it.
"""

import os

os.environ.setdefault("AUTHGATE_BACKEND", "python")
