//! ZVM - The Zig Virtual Machine
//! A lightweight, modular, and secure virtual machine engine for smart contracts
const std = @import("std");

// Import Shroud framework
pub const shroud = @import("shroud");

// Re-export core modules
pub const zvm = @import("zvm.zig");
pub const zevm = @import("zevm.zig");
pub const contract = @import("contract.zig");
pub const runtime = @import("runtime.zig");

// Legacy function for compatibility
pub fn advancedPrint() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("ZVM - The Zig Virtual Machine v0.1.0\n", .{});
    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush();
}

test "zvm module import" {
    const vm = zvm.VM.init();
    try std.testing.expect(vm.gas.limit == 0);
}
