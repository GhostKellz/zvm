//! Stack machine implementation for ZVM
//! Fixed-size stack with 1024 element capacity (EVM-compatible)

const std = @import("std");
const types = @import("../primitives/types.zig");
const U256 = types.U256;

pub const StackError = error{
    StackOverflow,
    StackUnderflow,
};

/// Stack machine with fixed 1024 element capacity
pub const Stack = struct {
    items: [MAX_DEPTH]U256,
    len: usize,

    pub const MAX_DEPTH = 1024;

    pub fn init() Stack {
        return .{
            .items = undefined, // Will be initialized as needed
            .len = 0,
        };
    }

    /// Push value onto stack
    pub fn push(self: *Stack, value: U256) StackError!void {
        if (self.len >= MAX_DEPTH) {
            return error.StackOverflow;
        }
        self.items[self.len] = value;
        self.len += 1;
    }

    /// Pop value from stack
    pub fn pop(self: *Stack) StackError!U256 {
        if (self.len == 0) {
            return error.StackUnderflow;
        }
        self.len -= 1;
        return self.items[self.len];
    }

    /// Peek at value without removing it
    /// peek_depth: 0 = top of stack, 1 = second from top, etc.
    pub fn peek(self: *const Stack, peek_depth: usize) StackError!U256 {
        if (peek_depth >= self.len) {
            return error.StackUnderflow;
        }
        return self.items[self.len - 1 - peek_depth];
    }

    /// Set value at depth
    pub fn set(self: *Stack, set_depth: usize, value: U256) StackError!void {
        if (set_depth >= self.len) {
            return error.StackUnderflow;
        }
        self.items[self.len - 1 - set_depth] = value;
    }

    /// Duplicate item at depth and push to top
    /// dup_depth: 0 = duplicate top (DUP1), 1 = duplicate second (DUP2), etc.
    pub fn dup(self: *Stack, dup_depth: usize) StackError!void {
        const value = try self.peek(dup_depth);
        try self.push(value);
    }

    /// Swap top with item at depth
    /// swap_depth: 1 = swap with second item (SWAP1), 2 = swap with third (SWAP2), etc.
    pub fn swap(self: *Stack, swap_depth: usize) StackError!void {
        if (swap_depth == 0 or swap_depth >= self.len) {
            return error.StackUnderflow;
        }

        const top_idx = self.len - 1;
        const swap_idx = self.len - 1 - swap_depth;

        const temp = self.items[top_idx];
        self.items[top_idx] = self.items[swap_idx];
        self.items[swap_idx] = temp;
    }

    /// Get current stack depth
    pub fn depth(self: *const Stack) usize {
        return self.len;
    }

    /// Check if stack is empty
    pub fn isEmpty(self: *const Stack) bool {
        return self.len == 0;
    }

    /// Clear the stack
    pub fn clear(self: *Stack) void {
        self.len = 0;
    }

    /// Get stack contents as slice (for debugging/testing)
    pub fn getItems(self: *const Stack) []const U256 {
        return self.items[0..self.len];
    }
};

// Tests
test "stack push and pop" {
    var stack = Stack.init();

    try stack.push(U256.fromU64(42));
    try stack.push(U256.fromU64(100));

    try std.testing.expectEqual(@as(usize, 2), stack.depth());

    const val1 = try stack.pop();
    try std.testing.expectEqual(@as(u64, 100), val1.toU64());

    const val2 = try stack.pop();
    try std.testing.expectEqual(@as(u64, 42), val2.toU64());

    try std.testing.expect(stack.isEmpty());
}

test "stack underflow" {
    var stack = Stack.init();
    try std.testing.expectError(error.StackUnderflow, stack.pop());
}

test "stack overflow" {
    var stack = Stack.init();

    // Fill to capacity
    for (0..Stack.MAX_DEPTH) |_| {
        try stack.push(U256.fromU64(1));
    }

    // Next push should overflow
    try std.testing.expectError(error.StackOverflow, stack.push(U256.fromU64(1)));
}

test "stack peek" {
    var stack = Stack.init();
    try stack.push(U256.fromU64(10));
    try stack.push(U256.fromU64(20));
    try stack.push(U256.fromU64(30));

    try std.testing.expectEqual(@as(u64, 30), (try stack.peek(0)).toU64());
    try std.testing.expectEqual(@as(u64, 20), (try stack.peek(1)).toU64());
    try std.testing.expectEqual(@as(u64, 10), (try stack.peek(2)).toU64());

    // Stack should be unchanged
    try std.testing.expectEqual(@as(usize, 3), stack.depth());
}

test "stack dup" {
    var stack = Stack.init();
    try stack.push(U256.fromU64(42));
    try stack.push(U256.fromU64(100));

    // DUP1 - duplicate top
    try stack.dup(0);
    try std.testing.expectEqual(@as(usize, 3), stack.depth());
    try std.testing.expectEqual(@as(u64, 100), (try stack.peek(0)).toU64());
    try std.testing.expectEqual(@as(u64, 100), (try stack.peek(1)).toU64());

    // DUP2 - duplicate second
    try stack.dup(1);
    try std.testing.expectEqual(@as(usize, 4), stack.depth());
    try std.testing.expectEqual(@as(u64, 100), (try stack.peek(0)).toU64());
}

test "stack swap" {
    var stack = Stack.init();
    try stack.push(U256.fromU64(10));
    try stack.push(U256.fromU64(20));
    try stack.push(U256.fromU64(30));

    // SWAP1 - swap top with second
    try stack.swap(1);
    try std.testing.expectEqual(@as(u64, 20), (try stack.peek(0)).toU64());
    try std.testing.expectEqual(@as(u64, 30), (try stack.peek(1)).toU64());
    try std.testing.expectEqual(@as(u64, 10), (try stack.peek(2)).toU64());

    // SWAP2 - swap top with third
    try stack.swap(2);
    try std.testing.expectEqual(@as(u64, 10), (try stack.peek(0)).toU64());
    try std.testing.expectEqual(@as(u64, 30), (try stack.peek(1)).toU64());
    try std.testing.expectEqual(@as(u64, 20), (try stack.peek(2)).toU64());
}
