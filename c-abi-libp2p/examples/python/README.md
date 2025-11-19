# Python: ping_two_nodes

Small `ctypes` script that:

1. Loads the compiled `libcabi_rust_libp2p.so`.
2. Creates two nodes (`listener` and `dialer`) through the C ABI.
3. Starts TCP listeners and initiates a connection.
4. Gives the nodes time to exchange libp2p ping traffic.

## Environment setup

1. Activate the dedicated Conda environment for the project:
   ```bash
   conda activate fidonext-abi
   ```
2. Create a local virtual environment for the Python example:
   ```bash
   cd /home/georgeb/fidonext-core/c-abi-libp2p/examples/python
   bash setup_env.sh
   source .venv/bin/activate
   ```

## Run the example

1. Build the Rust shared library (produces `target/debug/libcabi_rust_libp2p.so`):
   ```bash
   cd /home/georgeb/fidonext-core/c-abi-libp2p
   cargo build
   ```
2. (Optional) Tweak logging for verbose ping output:
   ```bash
   export RUST_LOG="info,peer=debug,ffi=debug"
   ```
3. Execute the Python client-to-client ping test:
   ```bash
   python3 examples/python/ping_two_nodes.py
   ```
4. Observe the console: successful runs show both peers listening, dialing, and
   establishing a connection. Ping RTTs appear in the Rust logs when
   `peer=debug` is enabled. The script automatically shuts down both nodes after
   ~5 seconds, so you may see a final “connection closed” warning—this is
   expected during teardown.

* By default the script expects `target/debug/libcabi_rust_libp2p.so`. Override
  the location via the `FIDONEXT_C_ABI` environment variable.
* Rust logs (`peer` / `ffi`) surface connection events and ping RTTs.
