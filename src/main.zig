const std = @import("std");
const zvm_root = @import("root.zig");
const zvm = @import("zvm.zig");
const zevm = @import("zevm.zig");
const contract = @import("contract.zig");
const runtime = @import("runtime.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        try printUsage();
        return;
    }
    
    const command = args[1];
    
    if (std.mem.eql(u8, command, "run")) {
        if (args.len < 3) {
            std.debug.print("Usage: zvm run <bytecode_file>\n", .{});
            return;
        }
        try runBytecode(allocator, args[2]);
    } else if (std.mem.eql(u8, command, "evm")) {
        if (args.len < 3) {
            std.debug.print("Usage: zvm evm <bytecode_file>\n", .{});
            return;
        }
        try runEvmBytecode(allocator, args[2]);
    } else if (std.mem.eql(u8, command, "demo")) {
        try runDemo(allocator);
    } else {
        try printUsage();
    }
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("ZVM - The Zig Virtual Machine v0.1.0\n\n", .{});
    try stdout.print("Usage:\n", .{});
    try stdout.print("  zvm run <bytecode_file>    Run ZVM native bytecode\n", .{});
    try stdout.print("  zvm evm <bytecode_file>    Run EVM-compatible bytecode\n", .{});
    try stdout.print("  zvm demo                   Run built-in demo\n", .{});
}

fn runBytecode(allocator: std.mem.Allocator, filepath: []const u8) !void {
    _ = allocator;
    
    std.debug.print("Running ZVM bytecode: {s}\n", .{filepath});
    
    // Demo bytecode: PUSH1 42, PUSH1 8, ADD, HALT
    const bytecode = [_]u8{
        @intFromEnum(zvm.Opcode.PUSH1), 42,
        @intFromEnum(zvm.Opcode.PUSH1), 8,
        @intFromEnum(zvm.Opcode.ADD),
        @intFromEnum(zvm.Opcode.HALT)
    };
    
    var vm = zvm.VM.init();
    vm.load_bytecode(&bytecode, 100000);
    
    std.debug.print("Starting execution...\n", .{});
    
    vm.run() catch |err| switch (err) {
        zvm.VMError.OutOfGas => {
            std.debug.print("Error: Out of gas\n", .{});
            return;
        },
        else => {
            std.debug.print("Error: {}\n", .{err});
            return;
        },
    };
    
    std.debug.print("Execution completed successfully!\n", .{});
    std.debug.print("Gas used: {}\n", .{vm.gas_used()});
    
    if (vm.stack.len > 0) {
        const result = vm.stack.peek(0) catch 0;
        std.debug.print("Result on stack: {}\n", .{result});
    }
}

fn runEvmBytecode(allocator: std.mem.Allocator, filepath: []const u8) !void {
    std.debug.print("Running EVM bytecode: {s}\n", .{filepath});
    
    var zevm_runtime = zevm.ZevmRuntime.init(allocator);
    defer zevm_runtime.deinit();
    
    // Demo EVM bytecode: PUSH1 42, PUSH1 8, ADD, STOP
    const bytecode = [_]u8{
        @intFromEnum(zevm.EvmOpcode.PUSH1), 42,
        @intFromEnum(zevm.EvmOpcode.PUSH1), 8,
        @intFromEnum(zevm.EvmOpcode.ADD),
        @intFromEnum(zevm.EvmOpcode.STOP)
    };
    
    std.debug.print("Starting EVM execution...\n", .{});
    
    const result = zevm_runtime.execute_evm(
        &bytecode,
        contract.AddressUtils.zero(),
        0,
        &[_]u8{},
        100000
    ) catch |err| {
        std.debug.print("Error: {}\n", .{err});
        return;
    };
    
    if (result.success) {
        std.debug.print("EVM execution completed successfully!\n", .{});
        std.debug.print("Gas used: {}\n", .{result.gas_used});
    } else {
        std.debug.print("EVM execution failed: {s}\n", .{result.error_msg orelse "Unknown error"});
    }
}

fn runDemo(allocator: std.mem.Allocator) !void {
    std.debug.print("=== ZVM Demo ===\n\n", .{});
    
    // Demo 1: Basic ZVM execution
    std.debug.print("1. Basic ZVM Execution\n", .{});
    var vm = zvm.VM.init();
    
    const zvm_bytecode = [_]u8{
        @intFromEnum(zvm.Opcode.PUSH1), 10,
        @intFromEnum(zvm.Opcode.PUSH1), 20,
        @intFromEnum(zvm.Opcode.ADD),
        @intFromEnum(zvm.Opcode.PUSH1), 5,
        @intFromEnum(zvm.Opcode.MUL),
        @intFromEnum(zvm.Opcode.HALT)
    };
    
    vm.load_bytecode(&zvm_bytecode, 100000);
    try vm.run();
    
    if (vm.stack.len > 0) {
        const result = try vm.stack.peek(0);
        std.debug.print("   Result: (10 + 20) * 5 = {}\n", .{result});
    }
    std.debug.print("   Gas used: {}\n\n", .{vm.gas_used()});
    
    // Demo 2: EVM compatibility
    std.debug.print("2. EVM Compatibility\n", .{});
    var zevm_runtime = zevm.ZevmRuntime.init(allocator);
    defer zevm_runtime.deinit();
    
    const evm_bytecode = [_]u8{
        @intFromEnum(zevm.EvmOpcode.PUSH1), 15,
        @intFromEnum(zevm.EvmOpcode.PUSH1), 25,
        @intFromEnum(zevm.EvmOpcode.ADD),
        @intFromEnum(zevm.EvmOpcode.PUSH1), 2,
        @intFromEnum(zevm.EvmOpcode.DIV),
        @intFromEnum(zevm.EvmOpcode.STOP)
    };
    
    const evm_result = try zevm_runtime.execute_evm(
        &evm_bytecode,
        contract.AddressUtils.zero(),
        0,
        &[_]u8{},
        100000
    );
    
    std.debug.print("   EVM execution success: {}\n", .{evm_result.success});
    std.debug.print("   Gas used: {}\n\n", .{evm_result.gas_used});
    
    // Demo 3: Contract deployment and execution
    std.debug.print("3. Smart Contract Runtime\n", .{});
    var contract_runtime = runtime.Runtime.init(allocator);
    defer contract_runtime.deinit();
    
    const contract_bytecode = [_]u8{
        @intFromEnum(zvm.Opcode.CALLER),
        @intFromEnum(zvm.Opcode.PUSH1), 100,
        @intFromEnum(zvm.Opcode.ADD),
        @intFromEnum(zvm.Opcode.HALT)
    };
    
    const deployer = contract.AddressUtils.random();
    const deploy_result = try contract_runtime.deploy_contract(&contract_bytecode, deployer, 0, 100000);
    
    if (deploy_result.success) {
        std.debug.print("   Contract deployed successfully!\n", .{});
        std.debug.print("   Deployment gas: {}\n", .{deploy_result.gas_used});
    }
    
    std.debug.print("\n=== Demo Complete ===\n", .{});
    
    // Print ecosystem integration info
    std.debug.print("\n🔗 ZVM Ecosystem Integration:\n", .{});
    std.debug.print("   • zcrypto: Cryptographic primitives (Ed25519, secp256k1, ChaCha20)\n", .{});
    std.debug.print("   • zwallet: HD wallet integration for account management\n", .{});
    std.debug.print("   • zsig: Message signing and verification\n", .{});
    std.debug.print("   • ghostbridge: gRPC communication with Rust blockchain\n", .{});
    std.debug.print("   • cns: Custom Name Service for domain resolution\n", .{});
    std.debug.print("   • tokioz: Async runtime for concurrent execution\n", .{});
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // Try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
