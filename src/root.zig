//! ZVM - Zig Virtual Machine v0.2.2
//! Root module that exports all ZVM functionality

const std = @import("std");

// Core ZVM modules
pub const zvm = @import("zvm.zig");
pub const contract = @import("contract.zig");
pub const database = @import("database.zig");
pub const runtime = @import("runtime.zig");

// Networking and communication
pub const networking = @import("networking.zig");

// CLI and RPC interfaces
pub const cli = @import("cli.zig");
pub const rpc = @import("rpc.zig");
pub const client = @import("client.zig");

// Re-export commonly used types
pub const Address = contract.Address;
pub const ExecutionResult = contract.ExecutionResult;
pub const ContractContext = contract.ContractContext;
pub const Storage = contract.Storage;

pub const VM = zvm.VM;
pub const Opcode = zvm.Opcode;

pub const DatabaseConfig = database.DatabaseConfig;
pub const PersistentStorage = database.PersistentStorage;

pub const EnhancedRuntimeVM = runtime.EnhancedRuntimeVM;
pub const EnhancedRuntimeHooks = runtime.EnhancedRuntimeHooks;
pub const Crypto = runtime.Crypto;

pub const ContractClient = networking.ContractClient;
pub const ContractServer = networking.ContractServer;
pub const NetworkConfig = networking.NetworkConfig;

pub const ZvmCli = cli.ZvmCli;
pub const CliConfig = cli.CliConfig;

pub const RpcServer = rpc.RpcServer;
pub const RpcConfig = rpc.RpcConfig;
pub const JsonRpc = rpc.JsonRpc;

pub const ZvmClient = client.ZvmClient;
pub const ClientConfig = client.ClientConfig;
pub const ContractBuilder = client.ContractBuilder;

// Version information
pub const version = "0.2.2";
pub const features = [_][]const u8{
    "WASM Runtime Integration",
    "Post-Quantum Cryptography (ML-DSA, ML-KEM)",
    "zqlite Persistent Storage",
    "QUIC/HTTP3 Networking",
    "CLI Interface",
    "JSON-RPC API",
    "REST API",
    "Client SDK",
};

// Legacy function for compatibility
pub fn advancedPrint() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("ZVM - The Zig Virtual Machine v{s}\n", .{version});
    try stdout.print("Features: {s}\n", .{features});
    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush();
}

test {
    // Import all modules to ensure they compile
    _ = zvm;
    _ = contract;
    _ = database;
    _ = runtime;
    _ = networking;
    _ = cli;
    _ = rpc;
    _ = client;
}
