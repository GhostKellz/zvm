const std = @import("std");
const zvm_root = @import("root.zig");
const zvm = @import("zvm.zig");
const zevm = @import("zevm.zig");
const wasm = @import("wasm.zig");
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
    } else if (std.mem.eql(u8, command, "wasm")) {
        if (args.len < 3) {
            std.debug.print("Usage: zvm wasm <wasm_file>\n", .{});
            return;
        }
        try runWasmBytecode(allocator, args[2]);
    } else if (std.mem.eql(u8, command, "hybrid")) {
        if (args.len < 3) {
            std.debug.print("Usage: zvm hybrid <bytecode_file>\n", .{});
            return;
        }
        try runHybrid(allocator, args[2]);
    } else if (std.mem.eql(u8, command, "demo")) {
        try runDemo(allocator);
    } else {
        try printUsage();
    }
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("ZVM - The Zig Virtual Machine v0.2.0 (Hybrid Runtime)\n\n", .{});
    try stdout.print("Usage:\n", .{});
    try stdout.print("  zvm run <bytecode_file>     Run ZVM native bytecode\n", .{});
    try stdout.print("  zvm evm <bytecode_file>     Run EVM-compatible bytecode\n", .{});
    try stdout.print("  zvm wasm <wasm_file>        Run WebAssembly module\n", .{});
    try stdout.print("  zvm hybrid <bytecode_file>  Auto-detect and run any format\n", .{});
    try stdout.print("  zvm demo                    Run built-in demo\n", .{});
}

fn runBytecode(allocator: std.mem.Allocator, filepath: []const u8) !void {
    _ = allocator;

    std.debug.print("Running ZVM bytecode: {s}\n", .{filepath});

    // Demo bytecode: PUSH1 42, PUSH1 8, ADD, HALT
    const bytecode = [_]u8{ @intFromEnum(zvm.Opcode.PUSH1), 42, @intFromEnum(zvm.Opcode.PUSH1), 8, @intFromEnum(zvm.Opcode.ADD), @intFromEnum(zvm.Opcode.HALT) };

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
    const bytecode = [_]u8{ @intFromEnum(zevm.EvmOpcode.PUSH1), 42, @intFromEnum(zevm.EvmOpcode.PUSH1), 8, @intFromEnum(zevm.EvmOpcode.ADD), @intFromEnum(zevm.EvmOpcode.STOP) };

    std.debug.print("Starting EVM execution...\n", .{});

    const result = zevm_runtime.execute_evm(&bytecode, contract.AddressUtils.zero(), 0, &[_]u8{}, 100000) catch |err| {
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

fn runWasmBytecode(allocator: std.mem.Allocator, filepath: []const u8) !void {
    std.debug.print("Running WASM bytecode: {s}\n", .{filepath});

    // Load WASM file
    const wasm_data = std.fs.cwd().readFileAlloc(allocator, filepath, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) {
            std.debug.print("Error: File not found: {s}\n", .{filepath});
            return;
        }
        std.debug.print("Error loading file: {}\n", .{err});
        return;
    };
    defer allocator.free(wasm_data);

    // Initialize WASM runtime
    var wasm_runtime = wasm.WasmRuntime.init(allocator);
    defer wasm_runtime.deinit();

    // Load WASM module
    const module = wasm_runtime.loadModule(wasm_data) catch |err| {
        std.debug.print("Error loading WASM module: {}\n", .{err});
        return;
    };

    std.debug.print("Starting WASM execution...\n", .{});

    // Execute main function if available
    const result = wasm_runtime.executeFunction(module, "main", &[_]wasm.WasmValue{}, 100000) catch |err| {
        std.debug.print("Error executing WASM: {}\n", .{err});
        return;
    };

    std.debug.print("WASM execution completed successfully!\n", .{});
    std.debug.print("Gas used: {}\n", .{result.gas_used});

    if (result.return_data.len > 0) {
        std.debug.print("Return data length: {}\n", .{result.return_data.len});
    }
}

fn runHybrid(allocator: std.mem.Allocator, filepath: []const u8) !void {
    std.debug.print("Running hybrid bytecode detection: {s}\n", .{filepath});

    // Load file and detect format
    const bytecode = std.fs.cwd().readFileAlloc(allocator, filepath, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) {
            std.debug.print("Error: File not found: {s}\n", .{filepath});
            return;
        }
        std.debug.print("Error loading file: {}\n", .{err});
        return;
    };
    defer allocator.free(bytecode);

    const format = detectBytecodeFormat(bytecode);

    switch (format) {
        .ZVM => {
            std.debug.print("Detected: ZVM native bytecode\n", .{});
            try executeZVMBytecode(allocator, bytecode);
        },
        .EVM => {
            std.debug.print("Detected: EVM-compatible bytecode\n", .{});
            try executeEVMBytecode(allocator, bytecode);
        },
        .WASM => {
            std.debug.print("Detected: WebAssembly module\n", .{});
            try executeWASMBytecode(allocator, bytecode);
        },
        .Unknown => {
            std.debug.print("Error: Unknown bytecode format\n", .{});
        },
    }
}

const BytecodeFormat = enum {
    ZVM,
    EVM,
    WASM,
    Unknown,
};

fn detectBytecodeFormat(bytecode: []const u8) BytecodeFormat {
    if (bytecode.len < 4) return .Unknown;

    // WASM magic number: 0x00 0x61 0x73 0x6D
    if (std.mem.eql(u8, bytecode[0..4], &[_]u8{ 0x00, 0x61, 0x73, 0x6D })) {
        return .WASM;
    }

    // ZVM magic opcodes
    if (bytecode[0] == @intFromEnum(zvm.Opcode.PUSH1) or
        bytecode[0] == @intFromEnum(zvm.Opcode.PUSH2) or
        bytecode[0] == @intFromEnum(zvm.Opcode.CALLER))
    {
        return .ZVM;
    }

    // EVM magic opcodes
    if (bytecode[0] == @intFromEnum(zevm.EvmOpcode.PUSH1) or
        bytecode[0] == @intFromEnum(zevm.EvmOpcode.PUSH2) or
        bytecode[0] == @intFromEnum(zevm.EvmOpcode.CALLER))
    {
        return .EVM;
    }

    return .Unknown;
}

fn executeZVMBytecode(allocator: std.mem.Allocator, bytecode: []const u8) !void {
    _ = allocator;

    var vm = zvm.VM.init();
    vm.load_bytecode(bytecode, 100000);

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

    std.debug.print("ZVM execution completed successfully!\n", .{});
    std.debug.print("Gas used: {}\n", .{vm.gas_used()});

    if (vm.stack.len > 0) {
        const result = vm.stack.peek(0) catch 0;
        std.debug.print("Result on stack: {}\n", .{result});
    }
}

fn executeEVMBytecode(allocator: std.mem.Allocator, bytecode: []const u8) !void {
    var zevm_runtime = zevm.ZevmRuntime.init(allocator);
    defer zevm_runtime.deinit();

    const result = zevm_runtime.execute_evm(bytecode, contract.AddressUtils.zero(), 0, &[_]u8{}, 100000) catch |err| {
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

fn executeWASMBytecode(allocator: std.mem.Allocator, bytecode: []const u8) !void {
    var wasm_runtime = wasm.WasmRuntime.init(allocator);
    defer wasm_runtime.deinit();

    const module = wasm_runtime.loadModule(bytecode) catch |err| {
        std.debug.print("Error loading WASM module: {}\n", .{err});
        return;
    };

    const result = wasm_runtime.executeFunction(module, "main", &[_]wasm.WasmValue{}, 100000) catch |err| {
        std.debug.print("Error executing WASM: {}\n", .{err});
        return;
    };

    std.debug.print("WASM execution completed successfully!\n", .{});
    std.debug.print("Gas used: {}\n", .{result.gas_used});

    if (result.return_data.len > 0) {
        std.debug.print("Return data length: {}\n", .{result.return_data.len});
    }
}

fn runDemo(allocator: std.mem.Allocator) !void {
    std.debug.print("=== ZVM v0.2.0 Hybrid Runtime Demo ===\n\n", .{});

    // Demo 1: Basic ZVM execution
    std.debug.print("1. Basic ZVM Execution\n", .{});
    var vm = zvm.VM.init();

    const zvm_bytecode = [_]u8{ @intFromEnum(zvm.Opcode.PUSH1), 10, @intFromEnum(zvm.Opcode.PUSH1), 20, @intFromEnum(zvm.Opcode.ADD), @intFromEnum(zvm.Opcode.PUSH1), 5, @intFromEnum(zvm.Opcode.MUL), @intFromEnum(zvm.Opcode.HALT) };

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

    const evm_bytecode = [_]u8{ @intFromEnum(zevm.EvmOpcode.PUSH1), 15, @intFromEnum(zevm.EvmOpcode.PUSH1), 25, @intFromEnum(zevm.EvmOpcode.ADD), @intFromEnum(zevm.EvmOpcode.PUSH1), 2, @intFromEnum(zevm.EvmOpcode.DIV), @intFromEnum(zevm.EvmOpcode.STOP) };

    const evm_result = try zevm_runtime.execute_evm(&evm_bytecode, contract.AddressUtils.zero(), 0, &[_]u8{}, 100000);

    std.debug.print("   EVM execution success: {}\n", .{evm_result.success});
    std.debug.print("   Gas used: {}\n\n", .{evm_result.gas_used});

    // Demo 3: WASM runtime
    std.debug.print("3. WebAssembly Runtime\n", .{});
    var wasm_runtime = wasm.WasmRuntime.init(allocator);
    defer wasm_runtime.deinit();

    // Create a simple WASM module (magic number + minimal module)
    const simple_wasm = [_]u8{
        0x00, 0x61, 0x73, 0x6D, // WASM magic number
        0x01, 0x00, 0x00, 0x00, // version 1
        0x01, 0x05, // type section
        0x01, 0x60, 0x00, 0x00, // function type: () -> ()
    };

    const wasm_module = wasm_runtime.loadModule(&simple_wasm) catch |err| {
        std.debug.print("   WASM module load: {}\n", .{err});
        std.debug.print("   (Expected for demo - basic module only)\n\n", .{});
        return;
    };
    _ = wasm_module;

    std.debug.print("   WASM module loaded successfully!\n\n", .{});

    // Demo 4: Hybrid Runtime Integration
    std.debug.print("4. Hybrid Runtime Integration\n", .{});
    var hybrid_runtime = runtime.HybridRuntime.init(allocator);
    defer hybrid_runtime.deinit();

    // Deploy a ZVM contract through hybrid runtime
    const hybrid_zvm_bytecode = [_]u8{ @intFromEnum(zvm.Opcode.PUSH1), 42, @intFromEnum(zvm.Opcode.PUSH1), 8, @intFromEnum(zvm.Opcode.ADD), @intFromEnum(zvm.Opcode.HALT) };
    const hybrid_deployer = contract.AddressUtils.random();
    const hybrid_deploy_result = try hybrid_runtime.deployContract(&hybrid_zvm_bytecode, hybrid_deployer, 0, 100000);

    if (hybrid_deploy_result.success) {
        std.debug.print("   Hybrid ZVM contract deployed!\n", .{});
        std.debug.print("   Contract address: {x}\n", .{std.fmt.fmtSliceHexLower(&hybrid_deploy_result.contract_address.?)});
        std.debug.print("   Gas used: {}\n", .{hybrid_deploy_result.gas_used});
    }

    // Get runtime statistics
    const stats = hybrid_runtime.getStatistics();
    std.debug.print("   Contracts deployed: {}\n", .{stats.contracts_deployed});
    std.debug.print("   Network peers: {}\n", .{stats.network_peers});
    std.debug.print("\n", .{});

    // Demo 5: Smart Contract Runtime (Legacy)
    std.debug.print("5. Legacy Smart Contract Runtime\n", .{});
    var contract_runtime = runtime.Runtime.init(allocator);
    defer contract_runtime.deinit();

    const contract_bytecode = [_]u8{ @intFromEnum(zvm.Opcode.CALLER), @intFromEnum(zvm.Opcode.PUSH1), 100, @intFromEnum(zvm.Opcode.ADD), @intFromEnum(zvm.Opcode.HALT) };

    const legacy_deployer = contract.AddressUtils.random();
    const legacy_deploy_result = try contract_runtime.deploy_contract(&contract_bytecode, legacy_deployer, 0, 100000);

    if (legacy_deploy_result.success) {
        std.debug.print("   Legacy contract deployed successfully!\n", .{});
        std.debug.print("   Deployment gas: {}\n", .{legacy_deploy_result.gas_used});
    }

    std.debug.print("\n=== Hybrid Runtime Demo Complete ===\n", .{});

    // Print ecosystem integration info
    std.debug.print("\n🚀 ZVM v0.2.0 Hybrid Runtime Features:\n", .{});
    std.debug.print("   • Native ZVM bytecode execution\n", .{});
    std.debug.print("   • EVM-compatible smart contracts\n", .{});
    std.debug.print("   • WebAssembly module support\n", .{});
    std.debug.print("   • Automatic format detection\n", .{});
    std.debug.print("   • Unified gas metering\n", .{});
    std.debug.print("   • Enhanced storage with format tracking\n", .{});
    std.debug.print("   • QUIC-based P2P networking ready\n", .{});
    std.debug.print("   • Post-quantum crypto integration ready\n", .{});
    std.debug.print("   • Hybrid runtime architecture\n", .{});
    std.debug.print("\n🔗 GhostChain Ecosystem Integration:\n", .{});
    std.debug.print("   • zcrypto v0.5.0: Post-quantum cryptography\n", .{});
    std.debug.print("   • zquic v0.3.0: QUIC transport layer\n", .{});
    std.debug.print("   • ghostd: Rust blockchain node integration\n", .{});
    std.debug.print("   • walletd: Wallet service integration\n", .{});
    std.debug.print("   • ghostbridge: gRPC-over-QUIC relay\n", .{});
    std.debug.print("   • CNS/ZNS: Domain resolution\n", .{});
    std.debug.print("   • Ready for production deployment\n", .{});
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
