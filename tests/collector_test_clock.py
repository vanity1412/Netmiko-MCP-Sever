"""Patch the clock in the collector and the modules that read CLI data."""
from contextlib import contextmanager, ExitStack
import sys
from unittest.mock import patch


@contextmanager
def patch_collector_clock(backend, clock):
    owners = {backend}
    for operation in (backend.read_cli_output, backend.junos_verified_write):
        # Benchmark and regression runs can load the monolithic baseline by path.
        if operation.__module__ != backend.__name__:
            owners.add(sys.modules[operation.__module__])

    with ExitStack() as stack:
        for owner in owners:
            stack.enter_context(patch.object(owner, 'time', clock))
        yield
