//! WASM Runtime - WebAssembly execution engine for ZVM
//! Provides WASM module loading, execution, and integration with ZVM native bytecode
const std = @import("std");
const zvm = @import("zvm.zig");
const contract = @import("contract.zig");

/// WASM Runtime Error types
pub const WasmError = error{
    InvalidModule,
    InvalidFunction,
    InvalidMemory,
    ExecutionFailed,
    OutOfMemory,
    TypeMismatch,
    StackOverflow,
    UnknownImport,
    OutOfGas,
};

/// WASM Value types
pub const WasmValueType = enum(u8) {
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0x7D,
    f64 = 0x7C,
    v128 = 0x7B,
    funcref = 0x70,
    externref = 0x6F,
};

/// WASM Values
pub const WasmValue = union(WasmValueType) {
    i32: i32,
    i64: i64,
    f32: f32,
    f64: f64,
    v128: u128,
    funcref: u32,
    externref: ?*anyopaque,
};

/// WASM Memory model
pub const WasmMemory = struct {
    data: []u8,
    min_pages: u32,
    max_pages: ?u32,
    allocator: std.mem.Allocator,

    const PAGE_SIZE = 65536; // 64KB pages

    pub fn init(allocator: std.mem.Allocator, min_pages: u32, max_pages: ?u32) !WasmMemory {
        const initial_size = min_pages * PAGE_SIZE;
        const data = try allocator.alloc(u8, initial_size);
        @memset(data, 0);

        return WasmMemory{
            .data = data,
            .min_pages = min_pages,
            .max_pages = max_pages,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *WasmMemory) void {
        self.allocator.free(self.data);
    }

    pub fn grow(self: *WasmMemory, pages: u32) !u32 {
        const current_pages = @as(u32, @intCast(self.data.len / PAGE_SIZE));
        const new_pages = current_pages + pages;

        if (self.max_pages) |max| {
            if (new_pages > max) return WasmError.OutOfMemory;
        }

        const new_size = new_pages * PAGE_SIZE;
        self.data = try self.allocator.realloc(self.data, new_size);

        // Zero out new pages
        const start = current_pages * PAGE_SIZE;
        @memset(self.data[start..], 0);

        return current_pages;
    }

    pub fn load(self: *WasmMemory, offset: u32, comptime T: type) !T {
        if (offset + @sizeOf(T) > self.data.len) return WasmError.InvalidMemory;

        const bytes = self.data[offset .. offset + @sizeOf(T)];
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }

    pub fn store(self: *WasmMemory, offset: u32, value: anytype) !void {
        const T = @TypeOf(value);
        if (offset + @sizeOf(T) > self.data.len) return WasmError.InvalidMemory;

        std.mem.writeInt(T, @ptrCast(self.data[offset .. offset + @sizeOf(T)]), value, .little);
    }

    pub fn loadBytes(self: *WasmMemory, offset: u32, len: u32) ![]u8 {
        if (offset + len > self.data.len) return WasmError.InvalidMemory;
        return self.data[offset .. offset + len];
    }

    pub fn storeBytes(self: *WasmMemory, offset: u32, bytes: []const u8) !void {
        if (offset + bytes.len > self.data.len) return WasmError.InvalidMemory;
        @memcpy(self.data[offset .. offset + bytes.len], bytes);
    }
};

/// WASM Stack for execution
pub const WasmStack = struct {
    values: std.ArrayList(WasmValue),

    pub fn init(allocator: std.mem.Allocator) WasmStack {
        return WasmStack{
            .values = std.ArrayList(WasmValue).init(allocator),
        };
    }

    pub fn deinit(self: *WasmStack) void {
        self.values.deinit();
    }

    pub fn push(self: *WasmStack, value: WasmValue) !void {
        try self.values.append(value);
    }

    pub fn pop(self: *WasmStack, comptime T: WasmValueType) !WasmValue {
        if (self.values.items.len == 0) return WasmError.StackOverflow;

        const value = self.values.pop() orelse return WasmError.StackOverflow;
        if (value != T) return WasmError.TypeMismatch;

        return value;
    }

    pub fn popI32(self: *WasmStack) !i32 {
        const value = try self.pop(.i32);
        return value.i32;
    }

    pub fn popI64(self: *WasmStack) !i64 {
        const value = try self.pop(.i64);
        return value.i64;
    }

    pub fn pushI32(self: *WasmStack, val: i32) !void {
        try self.push(WasmValue{ .i32 = val });
    }

    pub fn pushI64(self: *WasmStack, val: i64) !void {
        try self.push(WasmValue{ .i64 = val });
    }
};

/// WASM Function signature
pub const WasmFunction = struct {
    params: []const WasmValueType,
    results: []const WasmValueType,
    locals: []const WasmValueType,
    body: []const u8,

    pub fn init(allocator: std.mem.Allocator, params: []const WasmValueType, results: []const WasmValueType, locals: []const WasmValueType, body: []const u8) !WasmFunction {
        return WasmFunction{
            .params = try allocator.dupe(WasmValueType, params),
            .results = try allocator.dupe(WasmValueType, results),
            .locals = try allocator.dupe(WasmValueType, locals),
            .body = try allocator.dupe(u8, body),
        };
    }

    pub fn deinit(self: *WasmFunction, allocator: std.mem.Allocator) void {
        allocator.free(self.params);
        allocator.free(self.results);
        allocator.free(self.locals);
        allocator.free(self.body);
    }
};

/// WASM Module representation
pub const WasmModule = struct {
    functions: std.ArrayList(WasmFunction),
    memories: std.ArrayList(WasmMemory),
    exports: std.StringHashMap(u32),
    imports: std.StringHashMap(WasmImport),
    allocator: std.mem.Allocator,

    const WasmImport = struct {
        module: []const u8,
        name: []const u8,
        kind: ImportKind,

        const ImportKind = union(enum) {
            function: u32,
            memory: struct { min: u32, max: ?u32 },
            global: struct { type: WasmValueType, mutable: bool },
        };
    };

    pub fn init(allocator: std.mem.Allocator) WasmModule {
        return WasmModule{
            .functions = std.ArrayList(WasmFunction).init(allocator),
            .memories = std.ArrayList(WasmMemory).init(allocator),
            .exports = std.StringHashMap(u32).init(allocator),
            .imports = std.StringHashMap(WasmImport).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *WasmModule) void {
        for (self.functions.items) |*func| {
            func.deinit(self.allocator);
        }
        self.functions.deinit();

        for (self.memories.items) |*mem| {
            mem.deinit();
        }
        self.memories.deinit();

        self.exports.deinit();
        self.imports.deinit();
    }

    /// Load WASM module from bytecode (simplified parser)
    pub fn loadFromBytes(allocator: std.mem.Allocator, bytes: []const u8) !WasmModule {
        var module = WasmModule.init(allocator);

        // Simplified WASM parser - in reality this would be much more complex
        if (bytes.len < 8) return WasmError.InvalidModule;

        // Check magic number: 0x00 0x61 0x73 0x6D
        if (!std.mem.eql(u8, bytes[0..4], &[_]u8{ 0x00, 0x61, 0x73, 0x6D })) {
            return WasmError.InvalidModule;
        }

        // Check version: 0x01 0x00 0x00 0x00
        if (!std.mem.eql(u8, bytes[4..8], &[_]u8{ 0x01, 0x00, 0x00, 0x00 })) {
            return WasmError.InvalidModule;
        }

        // For demo purposes, create a simple function
        const demo_func = try WasmFunction.init(allocator, &[_]WasmValueType{.i32}, // params: i32
            &[_]WasmValueType{.i32}, // results: i32
            &[_]WasmValueType{}, // locals: none
            &[_]u8{ 0x20, 0x00, 0x0B } // body: local.get 0, end
        );
        try module.functions.append(demo_func);

        // Add default memory
        const memory = try WasmMemory.init(allocator, 1, 16); // 1 page min, 16 max
        try module.memories.append(memory);

        // Add export
        try module.exports.put("demo", 0);

        return module;
    }
};

/// WASM Host Function interface
pub const WasmHostFunction = struct {
    name: []const u8,
    params: []const WasmValueType,
    results: []const WasmValueType,
    implementation: *const fn(*WasmExecutionContext, []const WasmValue) WasmError![]WasmValue,
};

/// WASM Execution context with host functions
pub const WasmExecutionContext = struct {
    module: *WasmModule,
    stack: WasmStack,
    locals: std.ArrayList(WasmValue),
    gas_meter: *zvm.GasMeter,
    host_functions: std.StringHashMap(WasmHostFunction),
    contract_context: ?*contract.ContractContext,

    pub fn init(allocator: std.mem.Allocator, module: *WasmModule, gas_meter: *zvm.GasMeter) WasmExecutionContext {
        var ctx = WasmExecutionContext{
            .module = module,
            .stack = WasmStack.init(allocator),
            .locals = std.ArrayList(WasmValue).init(allocator),
            .gas_meter = gas_meter,
            .host_functions = std.StringHashMap(WasmHostFunction).init(allocator),
            .contract_context = null,
        };
        
        // Register default host functions
        ctx.registerDefaultHostFunctions() catch {};
        
        return ctx;
    }

    pub fn setContractContext(self: *WasmExecutionContext, context: *contract.ContractContext) void {
        self.contract_context = context;
    }

    fn registerDefaultHostFunctions(self: *WasmExecutionContext) !void {
        // Blockchain host functions
        try self.registerHostFunction("get_caller", &[_]WasmValueType{}, &[_]WasmValueType{.i64}, hostGetCaller);
        try self.registerHostFunction("get_origin", &[_]WasmValueType{}, &[_]WasmValueType{.i64}, hostGetOrigin);
        try self.registerHostFunction("get_value", &[_]WasmValueType{}, &[_]WasmValueType{.i64}, hostGetValue);
        try self.registerHostFunction("get_block_number", &[_]WasmValueType{}, &[_]WasmValueType{.i64}, hostGetBlockNumber);
        try self.registerHostFunction("get_block_timestamp", &[_]WasmValueType{}, &[_]WasmValueType{.i64}, hostGetBlockTimestamp);
        
        // Storage host functions
        try self.registerHostFunction("storage_load", &[_]WasmValueType{.i32}, &[_]WasmValueType{.i64}, hostStorageLoad);
        try self.registerHostFunction("storage_store", &[_]WasmValueType{.i32, .i64}, &[_]WasmValueType{}, hostStorageStore);
        
        // Crypto host functions
        try self.registerHostFunction("keccak256", &[_]WasmValueType{.i32, .i32}, &[_]WasmValueType{.i32}, hostKeccak256);
        try self.registerHostFunction("sha256", &[_]WasmValueType{.i32, .i32}, &[_]WasmValueType{.i32}, hostSha256);
        try self.registerHostFunction("ecrecover", &[_]WasmValueType{.i32, .i32}, &[_]WasmValueType{.i32}, hostEcrecover);
        
        // Debug/logging functions
        try self.registerHostFunction("debug_log", &[_]WasmValueType{.i32, .i32}, &[_]WasmValueType{}, hostDebugLog);
        try self.registerHostFunction("abort", &[_]WasmValueType{.i32, .i32, .i32, .i32}, &[_]WasmValueType{}, hostAbort);
    }

    pub fn registerHostFunction(self: *WasmExecutionContext, name: []const u8, params: []const WasmValueType, results: []const WasmValueType, implementation: *const fn(*WasmExecutionContext, []const WasmValue) WasmError![]WasmValue) !void {
        const host_func = WasmHostFunction{
            .name = try self.stack.values.allocator.dupe(u8, name),
            .params = try self.stack.values.allocator.dupe(WasmValueType, params),
            .results = try self.stack.values.allocator.dupe(WasmValueType, results),
            .implementation = implementation,
        };
        
        try self.host_functions.put(host_func.name, host_func);
    }

    // Host function implementations
    fn hostGetCaller(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        _ = args;
        if (ctx.contract_context) |contract_ctx| {
            // Convert address to u64 (simplified)
            var caller_u64: u64 = 0;
            for (contract_ctx.sender[0..8]) |byte| {
                caller_u64 = (caller_u64 << 8) | byte;
            }
            
            var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
            try result.append(WasmValue{ .i64 = @bitCast(caller_u64) });
            return try result.toOwnedSlice();
        }
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i64 = 0 });
        return try result.toOwnedSlice();
    }

    fn hostGetOrigin(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        return hostGetCaller(ctx, args); // Simplified: origin = caller
    }

    fn hostGetValue(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        _ = args;
        if (ctx.contract_context) |contract_ctx| {
            var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
            try result.append(WasmValue{ .i64 = @bitCast(@as(u64, @truncate(contract_ctx.value))) });
            return try result.toOwnedSlice();
        }
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i64 = 0 });
        return try result.toOwnedSlice();
    }

    fn hostGetBlockNumber(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        _ = args;
        if (ctx.contract_context) |contract_ctx| {
            var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
            try result.append(WasmValue{ .i64 = @bitCast(contract_ctx.block_number) });
            return try result.toOwnedSlice();
        }
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i64 = 0 });
        return try result.toOwnedSlice();
    }

    fn hostGetBlockTimestamp(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        _ = args;
        if (ctx.contract_context) |contract_ctx| {
            var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
            try result.append(WasmValue{ .i64 = @bitCast(@as(u64, @intCast(contract_ctx.block_timestamp))) });
            return try result.toOwnedSlice();
        }
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i64 = 0 });
        return try result.toOwnedSlice();
    }

    fn hostStorageLoad(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 1) return WasmError.TypeMismatch;
        if (ctx.contract_context) |contract_ctx| {
            const key_offset = @as(u32, @intCast(args[0].i32));
            
            // Load 32-byte key from memory
            if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
            const memory = &ctx.module.memories.items[0];
            
            if (key_offset + 32 > memory.data.len) return WasmError.InvalidMemory;
            
            // Convert bytes to u256
            var key: u256 = 0;
            for (memory.data[key_offset..key_offset + 32]) |byte| {
                key = (key << 8) | byte;
            }
            
            const value = contract_ctx.storage.load(key);
            
            var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
            try result.append(WasmValue{ .i64 = @bitCast(@as(u64, @truncate(value))) });
            return try result.toOwnedSlice();
        }
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i64 = 0 });
        return try result.toOwnedSlice();
    }

    fn hostStorageStore(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;
        if (ctx.contract_context) |contract_ctx| {
            const key_offset = @as(u32, @intCast(args[0].i32));
            const value = @as(u256, @intCast(@as(u64, @bitCast(args[1].i64))));
            
            // Load 32-byte key from memory
            if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
            const memory = &ctx.module.memories.items[0];
            
            if (key_offset + 32 > memory.data.len) return WasmError.InvalidMemory;
            
            // Convert bytes to u256
            var key: u256 = 0;
            for (memory.data[key_offset..key_offset + 32]) |byte| {
                key = (key << 8) | byte;
            }
            
            contract_ctx.storage.store(key, value);
        }
        
        return &[_]WasmValue{};
    }

    fn hostKeccak256(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;
        
        const data_offset = @as(u32, @intCast(args[0].i32));
        const data_len = @as(u32, @intCast(args[1].i32));
        
        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];
        
        if (data_offset + data_len > memory.data.len) return WasmError.InvalidMemory;
        
        const data = memory.data[data_offset..data_offset + data_len];
        const hash = @import("runtime.zig").Crypto.keccak256(data);
        
        // Store hash in memory and return offset
        const hash_offset = memory.data.len - 32;
        if (hash_offset + 32 > memory.data.len) {
            // Grow memory if needed
            _ = try memory.grow(1);
        }
        
        @memcpy(memory.data[hash_offset..hash_offset + 32], &hash);
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = @intCast(hash_offset) });
        return try result.toOwnedSlice();
    }

    fn hostSha256(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;
        
        const data_offset = @as(u32, @intCast(args[0].i32));
        const data_len = @as(u32, @intCast(args[1].i32));
        
        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];
        
        if (data_offset + data_len > memory.data.len) return WasmError.InvalidMemory;
        
        const data = memory.data[data_offset..data_offset + data_len];
        const hash = @import("runtime.zig").Crypto.sha256(data);
        
        // Store hash in memory and return offset
        const hash_offset = memory.data.len - 32;
        if (hash_offset + 32 > memory.data.len) {
            _ = try memory.grow(1);
        }
        
        @memcpy(memory.data[hash_offset..hash_offset + 32], &hash);
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = @intCast(hash_offset) });
        return try result.toOwnedSlice();
    }

    fn hostEcrecover(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;
        
        const hash_offset = @as(u32, @intCast(args[0].i32));
        const sig_offset = @as(u32, @intCast(args[1].i32));
        
        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];
        
        if (hash_offset + 32 > memory.data.len or sig_offset + 65 > memory.data.len) {
            return WasmError.InvalidMemory;
        }
        
        const message_hash = memory.data[hash_offset..hash_offset + 32];
        const signature = memory.data[sig_offset..sig_offset + 65];
        
        var hash_array: [32]u8 = undefined;
        var sig_array: [65]u8 = undefined;
        @memcpy(&hash_array, message_hash);
        @memcpy(&sig_array, signature);
        
        if (@import("runtime.zig").Crypto.ecrecover(hash_array, sig_array)) |recovered_addr| {
            // Store address in memory and return offset
            const addr_offset = memory.data.len - 20;
            if (addr_offset + 20 > memory.data.len) {
                _ = try memory.grow(1);
            }
            
            @memcpy(memory.data[addr_offset..addr_offset + 20], &recovered_addr);
            
            var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
            try result.append(WasmValue{ .i32 = @intCast(addr_offset) });
            return try result.toOwnedSlice();
        }
        
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = 0 });
        return try result.toOwnedSlice();
    }

    fn hostDebugLog(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;
        
        const msg_offset = @as(u32, @intCast(args[0].i32));
        const msg_len = @as(u32, @intCast(args[1].i32));
        
        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];
        
        if (msg_offset + msg_len > memory.data.len) return WasmError.InvalidMemory;
        
        const message = memory.data[msg_offset..msg_offset + msg_len];
        std.log.info("WASM Debug: {s}", .{message});
        
        return &[_]WasmValue{};
    }

    fn hostAbort(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 4) return WasmError.TypeMismatch;
        
        const msg_offset = @as(u32, @intCast(args[0].i32));
        const filename_offset = @as(u32, @intCast(args[1].i32));
        const line = @as(u32, @intCast(args[2].i32));
        const column = @as(u32, @intCast(args[3].i32));
        
        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];
        
        const message = if (msg_offset < memory.data.len) 
            memory.data[msg_offset..@min(msg_offset + 100, memory.data.len)]
        else 
            "Unknown error";
            
        const filename = if (filename_offset < memory.data.len)
            memory.data[filename_offset..@min(filename_offset + 50, memory.data.len)]
        else
            "unknown";
        
        std.log.err("WASM Abort: {s} at {s}:{}:{}", .{ message, filename, line, column });
        
        return WasmError.ExecutionFailed;
    }

    pub fn deinit(self: *WasmExecutionContext) void {
        self.stack.deinit();
        self.locals.deinit();
    }

    /// Execute a WASM function
    pub fn callFunction(self: *WasmExecutionContext, func_idx: u32, args: []const WasmValue) ![]WasmValue {
        if (func_idx >= self.module.functions.items.len) return WasmError.InvalidFunction;

        const func = &self.module.functions.items[func_idx];

        // Check parameter count
        if (args.len != func.params.len) return WasmError.TypeMismatch;

        // Push parameters to stack
        for (args) |arg| {
            try self.stack.push(arg);
        }

        // Initialize locals
        try self.locals.resize(func.params.len + func.locals.len);

        // Set parameter locals
        var i = func.params.len;
        while (i > 0) {
            i -= 1;
            self.locals.items[i] = self.stack.values.pop() orelse return WasmError.StackOverflow;
        }

        // Initialize local variables to zero
        for (func.locals, func.params.len..) |local_type, idx| {
            self.locals.items[idx] = switch (local_type) {
                .i32 => WasmValue{ .i32 = 0 },
                .i64 => WasmValue{ .i64 = 0 },
                .f32 => WasmValue{ .f32 = 0.0 },
                .f64 => WasmValue{ .f64 = 0.0 },
                else => WasmValue{ .i32 = 0 },
            };
        }

        // Execute function body (simplified interpreter)
        try self.executeInstructions(func.body);

        // Collect results
        var results = std.ArrayList(WasmValue).init(self.stack.values.allocator);
        defer results.deinit();

        for (func.results) |_| {
            if (self.stack.values.items.len == 0) return WasmError.StackOverflow;
            try results.insert(0, self.stack.values.pop() orelse return WasmError.StackOverflow);
        }

        return try results.toOwnedSlice();
    }

    /// Execute WASM instructions (simplified)
    fn executeInstructions(self: *WasmExecutionContext, instructions: []const u8) !void {
        var pc: usize = 0;

        while (pc < instructions.len) {
            const opcode = instructions[pc];
            pc += 1;

            // Consume gas for each instruction
            try self.gas_meter.consume(zvm.GasCost.BASE);

            switch (opcode) {
                // Control instructions
                0x0B => break, // end

                // Variable instructions
                0x20 => { // local.get
                    const local_idx = instructions[pc];
                    pc += 1;
                    if (local_idx >= self.locals.items.len) return WasmError.InvalidFunction;
                    try self.stack.push(self.locals.items[local_idx]);
                },
                0x21 => { // local.set
                    const local_idx = instructions[pc];
                    pc += 1;
                    if (local_idx >= self.locals.items.len) return WasmError.InvalidFunction;
                    if (self.stack.values.items.len == 0) return WasmError.StackOverflow;
                    self.locals.items[local_idx] = self.stack.values.pop() orelse return WasmError.StackOverflow;
                },

                // Numeric instructions
                0x41 => { // i32.const
                    // Simplified: read single byte value
                    const value = @as(i32, @intCast(instructions[pc]));
                    pc += 1;
                    try self.stack.pushI32(value);
                },
                0x6A => { // i32.add
                    const b = try self.stack.popI32();
                    const a = try self.stack.popI32();
                    try self.stack.pushI32(a + b);
                },
                0x6B => { // i32.sub
                    const b = try self.stack.popI32();
                    const a = try self.stack.popI32();
                    try self.stack.pushI32(a - b);
                },
                0x6C => { // i32.mul
                    const b = try self.stack.popI32();
                    const a = try self.stack.popI32();
                    try self.stack.pushI32(a * b);
                },

                // Memory instructions
                0x28 => { // i32.load
                    _ = instructions[pc]; // flags (align)
                    pc += 1;
                    _ = instructions[pc]; // offset
                    pc += 1;

                    const addr = try self.stack.popI32();
                    if (self.module.memories.items.len == 0) return WasmError.InvalidMemory;

                    const value = try self.module.memories.items[0].load(@intCast(addr), i32);
                    try self.stack.pushI32(value);
                },
                0x36 => { // i32.store
                    _ = instructions[pc]; // flags (align)
                    pc += 1;
                    _ = instructions[pc]; // offset
                    pc += 1;

                    const value = try self.stack.popI32();
                    const addr = try self.stack.popI32();
                    if (self.module.memories.items.len == 0) return WasmError.InvalidMemory;

                    try self.module.memories.items[0].store(@intCast(addr), value);
                },

                else => {
                    std.log.warn("Unknown WASM opcode: 0x{X:02}", .{opcode});
                    return WasmError.ExecutionFailed;
                },
            }
        }
    }
};

/// WASM Runtime - main interface
pub const WasmRuntime = struct {
    allocator: std.mem.Allocator,
    modules: std.ArrayList(*WasmModule),
    gas_used: u64,

    pub fn init(allocator: std.mem.Allocator) WasmRuntime {
        return WasmRuntime{
            .allocator = allocator,
            .modules = std.ArrayList(*WasmModule).init(allocator),
            .gas_used = 0,
        };
    }

    pub fn deinit(self: *WasmRuntime) void {
        for (self.modules.items) |module| {
            module.deinit();
            self.allocator.destroy(module);
        }
        self.modules.deinit();
    }

    /// Load WASM module from bytecode
    pub fn loadModule(self: *WasmRuntime, bytes: []const u8) !*WasmModule {
        const module = try self.allocator.create(WasmModule);
        module.* = try WasmModule.loadFromBytes(self.allocator, bytes);
        try self.modules.append(module);
        return module;
    }

    /// Execute WASM function with gas metering
    pub fn executeFunction(self: *WasmRuntime, module: *WasmModule, function_name: []const u8, args: []const WasmValue, gas_limit: u64) !contract.ExecutionResult {
        const func_idx = module.exports.get(function_name) orelse return contract.ExecutionResult{
            .success = false,
            .gas_used = 0,
            .return_data = &[_]u8{},
            .error_msg = "Function not found",
            .contract_address = null,
        };

        var gas_meter = zvm.GasMeter.init(gas_limit);
        var ctx = WasmExecutionContext.init(self.allocator, module, &gas_meter);
        defer ctx.deinit();

        const results = ctx.callFunction(func_idx, args) catch |err| {
            return contract.ExecutionResult{
                .success = false,
                .gas_used = gas_meter.used,
                .return_data = &[_]u8{},
                .error_msg = switch (err) {
                    WasmError.OutOfGas => "Out of gas",
                    WasmError.InvalidFunction => "Invalid function",
                    WasmError.ExecutionFailed => "Execution failed",
                    else => "Unknown error",
                },
                .contract_address = null,
            };
        };

        self.allocator.free(results);

        return contract.ExecutionResult{
            .success = true,
            .gas_used = gas_meter.used,
            .return_data = &[_]u8{}, // TODO: Convert results to bytes
            .error_msg = null,
            .contract_address = null,
        };
    }
};

// Tests
test "WASM module loading" {
    var runtime = WasmRuntime.init(std.testing.allocator);
    defer runtime.deinit();

    // Simple WASM module bytecode (magic + version)
    const wasm_bytes = [_]u8{
        0x00, 0x61, 0x73, 0x6D, // magic
        0x01, 0x00, 0x00, 0x00, // version
    };

    const module = try runtime.loadModule(&wasm_bytes);
    try std.testing.expect(module.functions.items.len > 0);
}

test "WASM execution" {
    var runtime = WasmRuntime.init(std.testing.allocator);
    defer runtime.deinit();

    const wasm_bytes = [_]u8{
        0x00, 0x61, 0x73, 0x6D, // magic
        0x01, 0x00, 0x00, 0x00, // version
    };

    const module = try runtime.loadModule(&wasm_bytes);

    const args = [_]WasmValue{WasmValue{ .i32 = 42 }};
    const result = try runtime.executeFunction(module, "demo", &args, 10000);

    try std.testing.expect(result.success);
}
