zvm: the VM

zvm = Zig Virtual Machine is a great name. Use it as:

“Execution engine for smart contracts – native IR + EVM compatibility”

Scope:

Has its own IR/bytecode designed for:

determinism

simple gas metering

post-quantum crypto hooks

Provides:

EVM compatibility layer (translate EVM bytecode → zvm IR or interpret natively)

Hedera integration (contracts as services)

Soroban bridge (compile your language down to WASM/Soroban where needed)

Language choice for implementation:

VM core:

Rust → easy crypto + tooling ecosystem, good async, accepted in infra world

Zig → tighter integration with your stack, leaner runtime

Given your world:

I’d do zvm in Rust or Zig; but if you want fast progress & libs: Rust core + Zig bindings is a really nice compromise.
