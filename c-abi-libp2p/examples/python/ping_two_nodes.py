#!/usr/bin/env python3
"""Minimal client-to-client example via the C ABI."""

import ctypes
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LIB = PROJECT_ROOT / "target" / "debug" / "libcabi_rust_libp2p.so"
LIB_PATH = Path(os.environ.get("FIDONEXT_C_ABI", DEFAULT_LIB))

os.environ.setdefault("RUST_LOG", "info,peer=info,ffi=info")

if not LIB_PATH.exists():
    sys.exit(
        f"Shared library not found at {LIB_PATH}. "
        "Run `cargo build` in c-abi-libp2p first or set FIDONEXT_C_ABI."
    )

lib = ctypes.CDLL(str(LIB_PATH))

# Status codes exported from the ABI.
CABI_STATUS_SUCCESS = 0
CABI_STATUS_NULL_POINTER = 1
CABI_STATUS_INVALID_ARGUMENT = 2

lib.cabi_init_tracing.restype = ctypes.c_int
lib.cabi_node_new.argtypes = [ctypes.c_bool]
lib.cabi_node_new.restype = ctypes.c_void_p
lib.cabi_node_listen.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.cabi_node_listen.restype = ctypes.c_int
lib.cabi_node_dial.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.cabi_node_dial.restype = ctypes.c_int
lib.cabi_node_free.argtypes = [ctypes.c_void_p]
lib.cabi_node_free.restype = None


def _check(status: int, context: str) -> None:
    if status == CABI_STATUS_SUCCESS:
        return
    if status == CABI_STATUS_NULL_POINTER:
        reason = "null pointer passed into ABI"
    elif status == CABI_STATUS_INVALID_ARGUMENT:
        reason = "invalid argument (multiaddr or UTF-8)"
    else:
        reason = "internal error – inspect Rust logs for details"
    raise RuntimeError(f"{context} failed: {reason} (status={status})")


class Node:
    def __init__(self, use_quic: bool = False) -> None:
        pointer = lib.cabi_node_new(ctypes.c_bool(use_quic))
        if not pointer:
            raise RuntimeError("cabi_node_new returned NULL, check Rust logs")
        self._ptr = ctypes.c_void_p(pointer)

    def listen(self, multiaddr: str) -> None:
        _check(
            lib.cabi_node_listen(self._ptr, multiaddr.encode("utf-8")),
            f"listen({multiaddr})",
        )

    def dial(self, multiaddr: str) -> None:
        _check(
            lib.cabi_node_dial(self._ptr, multiaddr.encode("utf-8")),
            f"dial({multiaddr})",
        )

    def close(self) -> None:
        if self._ptr:
            lib.cabi_node_free(self._ptr)
            self._ptr = None

    def __del__(self) -> None:  # pragma: no cover - best effort GC cleanup
        self.close()


def main() -> None:
    _check(lib.cabi_init_tracing(), "init tracing")

    listener_addr = "/ip4/127.0.0.1/tcp/41000"
    dialer_addr = "/ip4/127.0.0.1/tcp/41001"

    listener = Node()
    dialer = Node()

    try:
        listener.listen(listener_addr)
        dialer.listen(dialer_addr)

        # Give listeners a moment to start before dialing.
        time.sleep(0.5)

        dialer.dial(listener_addr)
        print(
            "Dialer connects to the listener. "
            "Inspect the Rust logs (peer/ping) for RTT output."
        )

        # Wait for several ping round-trips to be exchanged.
        time.sleep(5)
    finally:
        dialer.close()
        listener.close()


if __name__ == "__main__":
    main()

