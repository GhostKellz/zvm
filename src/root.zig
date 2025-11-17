//! ZVM - The Zig Virtual Machine
//! A zero-dependency, multi-chain smart contract execution engine
//!
//! Features:
//! - Pure Zig implementation with zero external dependencies
//! - Multi-chain support (Hedera, EVM, Soroban)
//! - KALIX-native compilation target
//! - Deterministic execution with gas metering
//! - Post-quantum crypto support

const std = @import("std");

// Re-export core modules
pub const types = @import("primitives/types.zig");
pub const bytecode = @import("bytecode/opcode.zig");
pub const interpreter = struct {
    pub const VM = @import("interpreter/vm.zig").VM;
    pub const Stack = @import("interpreter/stack.zig").Stack;
    pub const Memory = @import("interpreter/memory.zig").Memory;
    pub const ExecutionContext = @import("interpreter/vm.zig").ExecutionContext;
    pub const ExecutionResult = @import("interpreter/vm.zig").ExecutionResult;
};
pub const gas = @import("gas/meter.zig");
pub const state = struct {
    pub const Storage = @import("state/storage.zig").Storage;
    pub const TransientStorage = @import("state/storage.zig").TransientStorage;
    pub const JournaledState = @import("state/journaled.zig").JournaledState;
    pub const TransientStorageImpl = @import("state/transient.zig").TransientStorageImpl;
    pub const StorageAccess = @import("state/storage.zig").StorageAccess;
};
pub const hedera = struct {
    pub const syscalls = @import("chains/hedera/syscalls.zig");
    pub const mock = @import("chains/hedera/mock.zig");
    pub const HederaSyscalls = syscalls.HederaSyscalls;
    pub const HTSOperation = syscalls.HTSOperation;
    pub const HCSOperation = syscalls.HCSOperation;
    pub const HederaGas = syscalls.HederaGas;
    pub const MockHedera = mock.MockHedera;
};

// Re-export common types for convenience
pub const U256 = types.U256;
pub const Address = types.Address;
pub const Hash = types.Hash;
pub const Opcode = bytecode.Opcode;
pub const VM = interpreter.VM;
pub const Gas = gas.Gas;
pub const Storage = state.Storage;
pub const TransientStorage = state.TransientStorage;
pub const JournaledState = state.JournaledState;
pub const TransientStorageImpl = state.TransientStorageImpl;

test {
    std.testing.refAllDecls(@This());
}
