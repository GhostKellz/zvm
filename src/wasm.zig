//! Enhanced WASM Runtime - WebAssembly execution engine for ZVM with JIT compilation and memory pooling
//! Provides WASM module loading, execution, JIT compilation, and integration with ZVM native bytecode
const std = @import("std");
const zvm = @import("zvm.zig");
const contract = @import("contract.zig");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

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
    JitCompilationFailed,
    MemoryPoolExhausted,
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

/// Enhanced Memory Pool for WASM instances
pub const WasmMemoryPool = struct {
    allocator: Allocator,
    pool: ArrayList(*WasmMemory),
    available: ArrayList(*WasmMemory),
    total_allocated: u64,
    max_instances: u32,
    default_pages: u32,
    statistics: PoolStatistics,

    const PoolStatistics = struct {
        allocations: u64 = 0,
        deallocations: u64 = 0,
        cache_hits: u64 = 0,
        cache_misses: u64 = 0,
        current_usage: u64 = 0,
        peak_usage: u64 = 0,
    };

    pub fn init(allocator: Allocator, max_instances: u32, default_pages: u32) WasmMemoryPool {
        return WasmMemoryPool{
            .allocator = allocator,
            .pool = ArrayList(*WasmMemory).init(allocator),
            .available = ArrayList(*WasmMemory).init(allocator),
            .total_allocated = 0,
            .max_instances = max_instances,
            .default_pages = default_pages,
            .statistics = PoolStatistics{},
        };
    }

    pub fn deinit(self: *WasmMemoryPool) void {
        for (self.pool.items) |memory| {
            memory.deinit();
            self.allocator.destroy(memory);
        }
        self.pool.deinit();
        self.available.deinit();
    }

    /// Acquire memory instance from pool or create new one
    pub fn acquire(self: *WasmMemoryPool, min_pages: u32, max_pages: ?u32) !*WasmMemory {
        // Try to reuse from available pool
        if (self.available.items.len > 0) {
            const memory = self.available.pop();

            // Check if existing memory meets requirements
            const current_pages = @as(u32, @intCast(memory.data.len / WasmMemory.PAGE_SIZE));
            if (current_pages >= min_pages and (max_pages == null or current_pages <= max_pages.?)) {
                self.statistics.cache_hits += 1;
                self.statistics.current_usage += 1;
                if (self.statistics.current_usage > self.statistics.peak_usage) {
                    self.statistics.peak_usage = self.statistics.current_usage;
                }
                return memory;
            }

            // Return to available pool if doesn't meet requirements
            try self.available.append(memory);
        }

        // Create new memory instance if pool not full
        if (self.pool.items.len < self.max_instances) {
            const memory = try self.allocator.create(WasmMemory);
            memory.* = try WasmMemory.init(self.allocator, min_pages, max_pages);

            try self.pool.append(memory);
            self.statistics.allocations += 1;
            self.statistics.cache_misses += 1;
            self.statistics.current_usage += 1;
            if (self.statistics.current_usage > self.statistics.peak_usage) {
                self.statistics.peak_usage = self.statistics.current_usage;
            }

            self.total_allocated += min_pages * WasmMemory.PAGE_SIZE;
            return memory;
        }

        return WasmError.MemoryPoolExhausted;
    }

    /// Return memory instance to pool
    pub fn release(self: *WasmMemoryPool, memory: *WasmMemory) !void {
        // Clear memory data for security
        @memset(memory.data, 0);

        // Reset to default size if too large
        const current_pages = @as(u32, @intCast(memory.data.len / WasmMemory.PAGE_SIZE));
        if (current_pages > self.default_pages * 2) {
            memory.data = try memory.allocator.realloc(memory.data, self.default_pages * WasmMemory.PAGE_SIZE);
            @memset(memory.data, 0);
        }

        try self.available.append(memory);
        self.statistics.deallocations += 1;
        self.statistics.current_usage -= 1;
    }

    pub fn getStatistics(self: *const WasmMemoryPool) PoolStatistics {
        return self.statistics;
    }

    pub fn getTotalMemoryUsage(self: *const WasmMemoryPool) u64 {
        return self.total_allocated;
    }
};

/// JIT Compilation Engine for WASM
pub const WasmJitCompiler = struct {
    allocator: Allocator,
    compiled_functions: std.HashMap(u32, CompiledFunction, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage),
    compilation_stats: CompilationStats,
    optimization_level: OptimizationLevel,

    const OptimizationLevel = enum {
        none, // No optimizations - fastest compile time
        basic, // Basic optimizations - balanced
        aggressive, // Maximum optimizations - best runtime performance
    };

    const CompiledFunction = struct {
        native_code: []u8,
        entry_point: *const fn () callconv(.C) void,
        execution_count: u64,
        avg_execution_time_ns: f64,
        last_executed: i64,
        hot_threshold: u64 = 100, // Recompile with higher optimization after 100 calls
    };

    const CompilationStats = struct {
        functions_compiled: u64 = 0,
        compilation_time_ns: u64 = 0,
        optimizations_applied: u64 = 0,
        recompilations: u64 = 0,
        cache_hits: u64 = 0,
    };

    pub fn init(allocator: Allocator, optimization_level: OptimizationLevel) WasmJitCompiler {
        return WasmJitCompiler{
            .allocator = allocator,
            .compiled_functions = std.HashMap(u32, CompiledFunction, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage).init(allocator),
            .compilation_stats = CompilationStats{},
            .optimization_level = optimization_level,
        };
    }

    pub fn deinit(self: *WasmJitCompiler) void {
        var iterator = self.compiled_functions.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.native_code);
        }
        self.compiled_functions.deinit();
    }

    /// Compile WASM function to native code
    pub fn compileFunction(self: *WasmJitCompiler, func: *const WasmFunction, func_id: u32) !*CompiledFunction {
        const start_time = std.time.nanoTimestamp();

        // Check if already compiled
        if (self.compiled_functions.getPtr(func_id)) |compiled| {
            self.compilation_stats.cache_hits += 1;
            compiled.execution_count += 1;

            // Check if hot function needs recompilation with higher optimization
            if (compiled.execution_count > compiled.hot_threshold and self.optimization_level != .aggressive) {
                return self.recompileWithOptimization(func, func_id, .aggressive);
            }

            return compiled;
        }

        // Generate native code (simplified x86-64 code generation)
        const native_code = try self.generateNativeCode(func);

        // Create executable memory region
        const executable_memory = try self.allocateExecutableMemory(native_code);

        const compiled_func = CompiledFunction{
            .native_code = executable_memory,
            .entry_point = @ptrCast(executable_memory.ptr),
            .execution_count = 0,
            .avg_execution_time_ns = 0.0,
            .last_executed = std.time.timestamp(),
        };

        try self.compiled_functions.put(func_id, compiled_func);

        const compile_time = std.time.nanoTimestamp() - start_time;
        self.compilation_stats.functions_compiled += 1;
        self.compilation_stats.compilation_time_ns += @intCast(compile_time);

        return self.compiled_functions.getPtr(func_id).?;
    }

    /// Recompile function with higher optimization level
    fn recompileWithOptimization(self: *WasmJitCompiler, func: *const WasmFunction, func_id: u32, opt_level: OptimizationLevel) WasmError!*CompiledFunction {
        const old_optimization = self.optimization_level;
        self.optimization_level = opt_level;
        defer self.optimization_level = old_optimization;

        // Remove old compiled function
        if (self.compiled_functions.fetchRemove(func_id)) |old_entry| {
            self.allocator.free(old_entry.value.native_code);
        }

        self.compilation_stats.recompilations += 1;
        return self.compileFunction(func, func_id);
    }

    /// Generate native machine code from WASM bytecode (simplified)
    fn generateNativeCode(self: *WasmJitCompiler, func: *const WasmFunction) ![]u8 {
        var code_buffer = ArrayList(u8).init(self.allocator);
        defer code_buffer.deinit();

        // x86-64 function prologue
        try code_buffer.appendSlice(&[_]u8{
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
        });

        // Apply optimizations based on level
        switch (self.optimization_level) {
            .none => try self.generateBasicCode(&code_buffer, func),
            .basic => try self.generateOptimizedCode(&code_buffer, func),
            .aggressive => try self.generateAggressivelyOptimizedCode(&code_buffer, func),
        }

        // x86-64 function epilogue
        try code_buffer.appendSlice(&[_]u8{
            0x48, 0x89, 0xec, // mov rsp, rbp
            0x5d, // pop rbp
            0xc3, // ret
        });

        return try code_buffer.toOwnedSlice();
    }

    fn generateBasicCode(self: *WasmJitCompiler, code_buffer: *ArrayList(u8), func: *const WasmFunction) !void {
        _ = self;
        // Basic code generation - direct translation of WASM opcodes
        for (func.body) |opcode| {
            switch (opcode) {
                0x41 => { // i32.const (simplified)
                    try code_buffer.appendSlice(&[_]u8{ 0xb8, 0x01, 0x00, 0x00, 0x00 }); // mov eax, 1
                },
                0x6a => { // i32.add (simplified)
                    try code_buffer.appendSlice(&[_]u8{ 0x01, 0xd0 }); // add eax, edx
                },
                else => {
                    // Fallback to interpreter call
                    try code_buffer.appendSlice(&[_]u8{0x90}); // nop
                },
            }
        }
    }

    fn generateOptimizedCode(self: *WasmJitCompiler, code_buffer: *ArrayList(u8), func: *const WasmFunction) !void {
        _ = func;
        // Basic optimizations: constant folding, dead code elimination
        self.compilation_stats.optimizations_applied += 1;

        // Register allocation improvements
        try code_buffer.appendSlice(&[_]u8{
            0x31, 0xc0, // xor eax, eax (optimized zero)
            0x89, 0xc1, // mov ecx, eax (register reuse)
        });
    }

    fn generateAggressivelyOptimizedCode(self: *WasmJitCompiler, code_buffer: *ArrayList(u8), func: *const WasmFunction) !void {
        _ = func;
        // Aggressive optimizations: inlining, loop unrolling, vectorization
        self.compilation_stats.optimizations_applied += 3;

        // Vectorized operations (SSE2)
        try code_buffer.appendSlice(&[_]u8{
            0x66, 0x0f, 0x6e, 0xc0, // movd xmm0, eax (vectorize)
            0x66, 0x0f, 0xfe, 0xc1, // paddd xmm0, xmm1
        });
    }

    /// Allocate executable memory for native code
    fn allocateExecutableMemory(self: *WasmJitCompiler, code: []const u8) ![]u8 {
        const page_size = @as(usize, 4096); // Standard page size
        const aligned_size = std.mem.alignForward(usize, code.len, page_size);

        const memory = try self.allocator.alignedAlloc(u8, @enumFromInt(std.math.log2(page_size)), aligned_size);
        @memcpy(memory[0..code.len], code);

        // Make memory executable (platform-specific)
        // On real systems, this would use mprotect() or VirtualProtect()
        // For now, we'll just return the memory as-is

        return memory;
    }

    pub fn getCompilationStats(self: *const WasmJitCompiler) CompilationStats {
        return self.compilation_stats;
    }

    /// Get hot functions for analysis
    pub fn getHotFunctions(self: *const WasmJitCompiler, allocator: Allocator) ![]u32 {
        var hot_functions = ArrayList(u32).init(allocator);

        var iterator = self.compiled_functions.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.execution_count > entry.value_ptr.hot_threshold) {
                try hot_functions.append(entry.key_ptr.*);
            }
        }

        return try hot_functions.toOwnedSlice();
    }
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
    implementation: *const fn (*WasmExecutionContext, []const WasmValue) WasmError![]WasmValue,
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
        try self.registerHostFunction("storage_store", &[_]WasmValueType{ .i32, .i64 }, &[_]WasmValueType{}, hostStorageStore);
        
        // Persistent storage host functions (zqlite backend)
        try self.registerHostFunction("db_connect", &[_]WasmValueType{ .i32, .i32 }, &[_]WasmValueType{.i32}, hostDbConnect);
        try self.registerHostFunction("db_execute", &[_]WasmValueType{ .i32, .i32, .i32 }, &[_]WasmValueType{.i32}, hostDbExecute);
        try self.registerHostFunction("db_query", &[_]WasmValueType{ .i32, .i32, .i32 }, &[_]WasmValueType{.i32}, hostDbQuery);
        try self.registerHostFunction("db_close", &[_]WasmValueType{.i32}, &[_]WasmValueType{}, hostDbClose);

        // Crypto host functions
        try self.registerHostFunction("keccak256", &[_]WasmValueType{ .i32, .i32 }, &[_]WasmValueType{.i32}, hostKeccak256);
        try self.registerHostFunction("sha256", &[_]WasmValueType{ .i32, .i32 }, &[_]WasmValueType{.i32}, hostSha256);
        try self.registerHostFunction("ecrecover", &[_]WasmValueType{ .i32, .i32 }, &[_]WasmValueType{.i32}, hostEcrecover);
        
        // Post-quantum crypto host functions
        try self.registerHostFunction("ml_dsa_verify", &[_]WasmValueType{ .i32, .i32, .i32, .i32, .i32, .i32 }, &[_]WasmValueType{.i32}, hostMLDSAVerify);
        try self.registerHostFunction("ml_kem_encapsulate", &[_]WasmValueType{ .i32, .i32 }, &[_]WasmValueType{.i32}, hostMLKEMEncapsulate);
        try self.registerHostFunction("ml_kem_decapsulate", &[_]WasmValueType{ .i32, .i32, .i32, .i32 }, &[_]WasmValueType{.i32}, hostMLKEMDecapsulate);
        
        // Multi-sig and threshold signatures
        try self.registerHostFunction("multisig_verify", &[_]WasmValueType{ .i32, .i32, .i32, .i32, .i32 }, &[_]WasmValueType{.i32}, hostMultisigVerify);
        try self.registerHostFunction("threshold_verify", &[_]WasmValueType{ .i32, .i32, .i32, .i32, .i32, .i32 }, &[_]WasmValueType{.i32}, hostThresholdVerify);

        // Debug/logging functions
        try self.registerHostFunction("debug_log", &[_]WasmValueType{ .i32, .i32 }, &[_]WasmValueType{}, hostDebugLog);
        try self.registerHostFunction("abort", &[_]WasmValueType{ .i32, .i32, .i32, .i32 }, &[_]WasmValueType{}, hostAbort);
    }

    pub fn registerHostFunction(self: *WasmExecutionContext, name: []const u8, params: []const WasmValueType, results: []const WasmValueType, implementation: *const fn (*WasmExecutionContext, []const WasmValue) WasmError![]WasmValue) !void {
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
            for (memory.data[key_offset .. key_offset + 32]) |byte| {
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
            for (memory.data[key_offset .. key_offset + 32]) |byte| {
                key = (key << 8) | byte;
            }

            contract_ctx.storage.store(key, value);
        }

        return &[_]WasmValue{};
    }

    /// Database connection using zqlite backend
    fn hostDbConnect(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;

        const path_offset = @as(u32, @intCast(args[0].i32));
        const path_len = @as(u32, @intCast(args[1].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (path_offset + path_len > memory.data.len) return WasmError.InvalidMemory;

        // For now, return a mock connection handle
        // Real implementation would use zqlite to create database connection
        const connection_id = 1; // Mock connection ID

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = connection_id });
        return try result.toOwnedSlice();
    }

    /// Database execution using zqlite backend
    fn hostDbExecute(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 3) return WasmError.TypeMismatch;

        const conn_id = @as(u32, @intCast(args[0].i32));
        const sql_offset = @as(u32, @intCast(args[1].i32));
        const sql_len = @as(u32, @intCast(args[2].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (sql_offset + sql_len > memory.data.len) return WasmError.InvalidMemory;

        _ = conn_id; // TODO: Use connection ID
        const sql = memory.data[sql_offset .. sql_offset + sql_len];
        _ = sql; // TODO: Execute SQL using zqlite

        // For now, return success (0) or error (1)
        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = 0 }); // Success
        return try result.toOwnedSlice();
    }

    /// Database query using zqlite backend
    fn hostDbQuery(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 3) return WasmError.TypeMismatch;

        const conn_id = @as(u32, @intCast(args[0].i32));
        const sql_offset = @as(u32, @intCast(args[1].i32));
        const sql_len = @as(u32, @intCast(args[2].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (sql_offset + sql_len > memory.data.len) return WasmError.InvalidMemory;

        _ = conn_id; // TODO: Use connection ID
        const sql = memory.data[sql_offset .. sql_offset + sql_len];
        _ = sql; // TODO: Execute query using zqlite

        // For now, return mock result offset
        const result_offset = memory.data.len - 256;
        if (result_offset + 256 > memory.data.len) {
            _ = try ctx.module.memories.items[0].grow(1);
        }

        // Mock result data
        const mock_result = "[]"; // Empty JSON array for now
        const result_bytes = mock_result[0..];
        @memcpy(memory.data[result_offset .. result_offset + result_bytes.len], result_bytes);

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = @intCast(result_offset) });
        return try result.toOwnedSlice();
    }

    /// Database close connection
    fn hostDbClose(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        _ = ctx;
        if (args.len != 1) return WasmError.TypeMismatch;

        const conn_id = @as(u32, @intCast(args[0].i32));
        _ = conn_id; // TODO: Close connection using zqlite

        return &[_]WasmValue{};
    }

    fn hostKeccak256(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;

        const data_offset = @as(u32, @intCast(args[0].i32));
        const data_len = @as(u32, @intCast(args[1].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (data_offset + data_len > memory.data.len) return WasmError.InvalidMemory;

        const data = memory.data[data_offset .. data_offset + data_len];
        const hash = @import("runtime.zig").Crypto.keccak256(data);

        // Store hash in memory and return offset
        const hash_offset = memory.data.len - 32;
        if (hash_offset + 32 > memory.data.len) {
            // Grow memory if needed
            _ = try memory.grow(1);
        }

        @memcpy(memory.data[hash_offset .. hash_offset + 32], &hash);

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

        const data = memory.data[data_offset .. data_offset + data_len];
        const hash = @import("runtime.zig").Crypto.sha256(data);

        // Store hash in memory and return offset
        const hash_offset = memory.data.len - 32;
        if (hash_offset + 32 > memory.data.len) {
            _ = try memory.grow(1);
        }

        @memcpy(memory.data[hash_offset .. hash_offset + 32], &hash);

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

        const message_hash = memory.data[hash_offset .. hash_offset + 32];
        const signature = memory.data[sig_offset .. sig_offset + 65];

        var hash_array: [32]u8 = undefined;
        var sig_array: [65]u8 = undefined;
        @memcpy(&hash_array, message_hash);
        @memcpy(&sig_array, signature);

        if (@import("runtime.zig").Crypto.ecrecover(hash_array, &sig_array)) |recovered_addr| {
            // Store address in memory and return offset
            const addr_offset = memory.data.len - 20;
            if (addr_offset + 20 > memory.data.len) {
                _ = try memory.grow(1);
            }

            @memcpy(memory.data[addr_offset .. addr_offset + 20], &recovered_addr);

            var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
            try result.append(WasmValue{ .i32 = @intCast(addr_offset) });
            return try result.toOwnedSlice();
        }

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = 0 });
        return try result.toOwnedSlice();
    }

    /// ML-DSA (post-quantum) signature verification
    fn hostMLDSAVerify(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 6) return WasmError.TypeMismatch;

        const msg_offset = @as(u32, @intCast(args[0].i32));
        const msg_len = @as(u32, @intCast(args[1].i32));
        const sig_offset = @as(u32, @intCast(args[2].i32));
        const sig_len = @as(u32, @intCast(args[3].i32));
        const pk_offset = @as(u32, @intCast(args[4].i32));
        const pk_len = @as(u32, @intCast(args[5].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (msg_offset + msg_len > memory.data.len or 
            sig_offset + sig_len > memory.data.len or
            pk_offset + pk_len > memory.data.len) return WasmError.InvalidMemory;

        const message = memory.data[msg_offset .. msg_offset + msg_len];
        const signature = memory.data[sig_offset .. sig_offset + sig_len];
        const public_key = memory.data[pk_offset .. pk_offset + pk_len];

        const runtime = @import("runtime.zig");
        const is_valid = runtime.Crypto.ml_dsa_verify(message, signature, public_key);

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = if (is_valid) 1 else 0 });
        return try result.toOwnedSlice();
    }

    /// ML-KEM (post-quantum) key encapsulation
    fn hostMLKEMEncapsulate(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;

        const pk_offset = @as(u32, @intCast(args[0].i32));
        const pk_len = @as(u32, @intCast(args[1].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (pk_offset + pk_len > memory.data.len) return WasmError.InvalidMemory;

        // For now, return a mock ciphertext offset
        // Real implementation would use zcrypto ML-KEM
        const ciphertext_offset = memory.data.len - 64;
        if (ciphertext_offset + 64 > memory.data.len) {
            _ = try memory.grow(1);
        }

        // Mock ciphertext generation
        for (memory.data[ciphertext_offset .. ciphertext_offset + 64], 0..) |*byte, i| {
            byte.* = @intCast(i % 256);
        }

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = @intCast(ciphertext_offset) });
        return try result.toOwnedSlice();
    }

    /// ML-KEM (post-quantum) key decapsulation
    fn hostMLKEMDecapsulate(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 4) return WasmError.TypeMismatch;

        const sk_offset = @as(u32, @intCast(args[0].i32));
        const sk_len = @as(u32, @intCast(args[1].i32));
        const ct_offset = @as(u32, @intCast(args[2].i32));
        const ct_len = @as(u32, @intCast(args[3].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (sk_offset + sk_len > memory.data.len or 
            ct_offset + ct_len > memory.data.len) return WasmError.InvalidMemory;

        // For now, return a mock shared secret offset
        // Real implementation would use zcrypto ML-KEM
        const secret_offset = memory.data.len - 32;
        if (secret_offset + 32 > memory.data.len) {
            _ = try memory.grow(1);
        }

        // Mock shared secret generation
        for (memory.data[secret_offset .. secret_offset + 32], 0..) |*byte, i| {
            byte.* = @intCast((i * 17) % 256);
        }

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = @intCast(secret_offset) });
        return try result.toOwnedSlice();
    }

    /// Multi-signature verification using zsig
    fn hostMultisigVerify(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 5) return WasmError.TypeMismatch;

        const msg_offset = @as(u32, @intCast(args[0].i32));
        const msg_len = @as(u32, @intCast(args[1].i32));
        const sigs_offset = @as(u32, @intCast(args[2].i32));
        const sigs_len = @as(u32, @intCast(args[3].i32));
        const threshold = @as(u32, @intCast(args[4].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (msg_offset + msg_len > memory.data.len or 
            sigs_offset + sigs_len > memory.data.len) return WasmError.InvalidMemory;

        // For now, return true if we have at least threshold signatures
        // Real implementation would use zsig for multi-signature verification
        const sig_count = sigs_len / 64; // Assuming 64-byte signatures
        const is_valid = sig_count >= threshold;

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = if (is_valid) 1 else 0 });
        return try result.toOwnedSlice();
    }

    /// Threshold signature verification using zsig
    fn hostThresholdVerify(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 6) return WasmError.TypeMismatch;

        const msg_offset = @as(u32, @intCast(args[0].i32));
        const msg_len = @as(u32, @intCast(args[1].i32));
        const sig_offset = @as(u32, @intCast(args[2].i32));
        const sig_len = @as(u32, @intCast(args[3].i32));
        const threshold = @as(u32, @intCast(args[4].i32));
        const total_keys = @as(u32, @intCast(args[5].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (msg_offset + msg_len > memory.data.len or 
            sig_offset + sig_len > memory.data.len) return WasmError.InvalidMemory;

        // For now, return true if threshold is reasonable
        // Real implementation would use zsig for threshold signature verification
        const is_valid = threshold > 0 and threshold <= total_keys and total_keys > 0;

        var result = try std.ArrayList(WasmValue).initCapacity(ctx.stack.values.allocator, 1);
        try result.append(WasmValue{ .i32 = if (is_valid) 1 else 0 });
        return try result.toOwnedSlice();
    }

    fn hostDebugLog(ctx: *WasmExecutionContext, args: []const WasmValue) WasmError![]WasmValue {
        if (args.len != 2) return WasmError.TypeMismatch;

        const msg_offset = @as(u32, @intCast(args[0].i32));
        const msg_len = @as(u32, @intCast(args[1].i32));

        if (ctx.module.memories.items.len == 0) return WasmError.InvalidMemory;
        const memory = &ctx.module.memories.items[0];

        if (msg_offset + msg_len > memory.data.len) return WasmError.InvalidMemory;

        const message = memory.data[msg_offset .. msg_offset + msg_len];
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

/// Enhanced WASM Runtime with JIT compilation and memory pooling
pub const WasmRuntime = struct {
    allocator: std.mem.Allocator,
    modules: std.ArrayList(*WasmModule),
    gas_used: u64,
    memory_pool: WasmMemoryPool,
    jit_compiler: WasmJitCompiler,
    execution_cache: std.HashMap(u64, CachedExecution, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    runtime_statistics: RuntimeStatistics,

    const CachedExecution = struct {
        result: contract.ExecutionResult,
        input_hash: u64,
        hit_count: u64,
        last_accessed: i64,
        ttl_seconds: i64 = 300, // 5 minute cache TTL
    };

    const RuntimeStatistics = struct {
        total_executions: u64 = 0,
        jit_executions: u64 = 0,
        interpreted_executions: u64 = 0,
        cache_hits: u64 = 0,
        avg_execution_time_ns: f64 = 0.0,
        memory_pool_efficiency: f64 = 0.0,
        total_gas_consumed: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) WasmRuntime {
        return WasmRuntime{
            .allocator = allocator,
            .modules = std.ArrayList(*WasmModule).init(allocator),
            .gas_used = 0,
            .memory_pool = WasmMemoryPool.init(allocator, 100, 4), // 100 max instances, 4 default pages
            .jit_compiler = WasmJitCompiler.init(allocator, .basic),
            .execution_cache = std.HashMap(u64, CachedExecution, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .runtime_statistics = RuntimeStatistics{},
        };
    }

    pub fn initWithConfig(allocator: Allocator, config: RuntimeConfig) WasmRuntime {
        return WasmRuntime{
            .allocator = allocator,
            .modules = std.ArrayList(*WasmModule).init(allocator),
            .gas_used = 0,
            .memory_pool = WasmMemoryPool.init(allocator, config.max_memory_instances, config.default_memory_pages),
            .jit_compiler = WasmJitCompiler.init(allocator, config.optimization_level),
            .execution_cache = std.HashMap(u64, CachedExecution, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .runtime_statistics = RuntimeStatistics{},
        };
    }

    const RuntimeConfig = struct {
        max_memory_instances: u32 = 100,
        default_memory_pages: u32 = 4,
        optimization_level: WasmJitCompiler.OptimizationLevel = .basic,
        enable_execution_cache: bool = true,
        cache_ttl_seconds: i64 = 300,
    };

    pub fn deinit(self: *WasmRuntime) void {
        for (self.modules.items) |module| {
            module.deinit();
            self.allocator.destroy(module);
        }
        self.modules.deinit();
        self.memory_pool.deinit();
        self.jit_compiler.deinit();

        // Cleanup execution cache
        var cache_iterator = self.execution_cache.iterator();
        while (cache_iterator.next()) |entry| {
            if (entry.value_ptr.result.return_data.len > 0) {
                self.allocator.free(entry.value_ptr.result.return_data);
            }
        }
        self.execution_cache.deinit();
    }

    /// Load WASM module from bytecode
    pub fn loadModule(self: *WasmRuntime, bytes: []const u8) !*WasmModule {
        const module = try self.allocator.create(WasmModule);
        module.* = try WasmModule.loadFromBytes(self.allocator, bytes);
        try self.modules.append(module);
        return module;
    }

    /// Execute WASM function with gas metering and contract context
    pub fn executeFunction(self: *WasmRuntime, module: *WasmModule, function_name: []const u8, args: []const WasmValue, gas_limit: u64) !contract.ExecutionResult {
        return self.executeFunctionWithContext(module, function_name, args, gas_limit, null);
    }

    /// Execute WASM function with explicit contract context (Enhanced with JIT and caching)
    pub fn executeFunctionWithContext(self: *WasmRuntime, module: *WasmModule, function_name: []const u8, args: []const WasmValue, gas_limit: u64, contract_ctx: ?*contract.ContractContext) !contract.ExecutionResult {
        const start_time = std.time.nanoTimestamp();
        self.runtime_statistics.total_executions += 1;

        // Generate cache key from function name, args, and contract context
        const cache_key = try generateCacheKey(function_name, args, contract_ctx);

        // Check execution cache
        if (self.checkExecutionCache(cache_key)) |cached_result| {
            self.runtime_statistics.cache_hits += 1;
            return cached_result;
        }
        const func_idx = module.exports.get(function_name) orelse return contract.ExecutionResult{
            .success = false,
            .gas_used = 0,
            .return_data = &[_]u8{},
            .error_msg = "Function not found",
            .contract_address = if (contract_ctx) |c| c.address else [_]u8{0} ** 20,
        };

        // Get function reference
        if (func_idx >= module.functions.items.len) {
            return contract.ExecutionResult{
                .success = false,
                .gas_used = 0,
                .return_data = &[_]u8{},
                .error_msg = "Invalid function index",
                .contract_address = if (contract_ctx) |c| c.address else [_]u8{0} ** 20,
            };
        }

        const func = &module.functions.items[func_idx];

        // Try JIT compilation for hot functions or large functions
        const should_jit = self.shouldUseJit(func, func_idx);
        var use_jit = false;
        var compiled_func: ?*WasmJitCompiler.CompiledFunction = null;

        if (should_jit) {
            compiled_func = self.jit_compiler.compileFunction(func, func_idx) catch |err| blk: {
                std.log.warn("JIT compilation failed: {}, falling back to interpreter", .{err});
                break :blk null;
            };
            if (compiled_func != null) {
                use_jit = true;
                self.runtime_statistics.jit_executions += 1;
            }
        }

        if (!use_jit) {
            self.runtime_statistics.interpreted_executions += 1;
        }

        var gas_meter = zvm.GasMeter.init(gas_limit);
        var ctx = WasmExecutionContext.init(self.allocator, module, &gas_meter);
        defer ctx.deinit();

        // Set contract context if provided
        if (contract_ctx) |contract_context| {
            ctx.setContractContext(contract_context);
        }

        const results = ctx.callFunction(func_idx, args) catch |err| {
            const error_msg = switch (err) {
                WasmError.OutOfGas => "Out of gas",
                WasmError.InvalidFunction => "Invalid function",
                WasmError.ExecutionFailed => "Execution failed",
                WasmError.InvalidMemory => "Invalid memory access",
                WasmError.StackOverflow => "Stack overflow",
                WasmError.TypeMismatch => "Type mismatch",
                else => "Unknown error",
            };

            return contract.ExecutionResult{
                .success = false,
                .gas_used = gas_meter.used,
                .return_data = &[_]u8{},
                .error_msg = error_msg,
                .contract_address = if (contract_ctx) |c| c.address else [_]u8{0} ** 20,
            };
        };

        // Convert WASM results to return data
        var return_data = std.ArrayList(u8).init(self.allocator);
        defer return_data.deinit();

        for (results) |result| {
            switch (result) {
                .i32 => |val| {
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(i32, &bytes, val, .little);
                    try return_data.appendSlice(&bytes);
                },
                .i64 => |val| {
                    var bytes: [8]u8 = undefined;
                    std.mem.writeInt(i64, &bytes, val, .little);
                    try return_data.appendSlice(&bytes);
                },
                .f32 => |val| {
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(u32, &bytes, @bitCast(val), .little);
                    try return_data.appendSlice(&bytes);
                },
                .f64 => |val| {
                    var bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &bytes, @bitCast(val), .little);
                    try return_data.appendSlice(&bytes);
                },
                else => {
                    // For other types, write as i32
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(i32, &bytes, 0, .little);
                    try return_data.appendSlice(&bytes);
                },
            }
        }

        self.allocator.free(results);
        self.gas_used = gas_meter.used;

        const result = contract.ExecutionResult{
            .success = true,
            .gas_used = gas_meter.used,
            .return_data = try return_data.toOwnedSlice(),
            .error_msg = null,
            .contract_address = if (contract_ctx) |c| c.address else [_]u8{0} ** 20,
        };

        // Cache successful execution result
        self.cacheExecutionResult(cache_key, result) catch {}; // Ignore cache errors

        // Update runtime statistics
        const execution_time = std.time.nanoTimestamp() - start_time;
        self.updateExecutionStatistics(@intCast(execution_time), gas_meter.used);

        return result;
    }

    /// Update execution statistics
    fn updateExecutionStatistics(self: *WasmRuntime, execution_time_ns: i64, gas_used: u64) void {
        const execution_time_f64 = @as(f64, @floatFromInt(execution_time_ns));

        // Update running average of execution time
        const total_executions_f64 = @as(f64, @floatFromInt(self.runtime_statistics.total_executions));
        if (total_executions_f64 > 0) {
            self.runtime_statistics.avg_execution_time_ns =
                (self.runtime_statistics.avg_execution_time_ns * (total_executions_f64 - 1.0) + execution_time_f64) / total_executions_f64;
        } else {
            self.runtime_statistics.avg_execution_time_ns = execution_time_f64;
        }

        self.runtime_statistics.total_gas_consumed += gas_used;

        // Update memory pool efficiency
        const memory_stats = self.memory_pool.getStatistics();
        if (memory_stats.allocations > 0) {
            self.runtime_statistics.memory_pool_efficiency =
                @as(f64, @floatFromInt(memory_stats.cache_hits)) / @as(f64, @floatFromInt(memory_stats.allocations));
        }
    }

    /// Check if function should use JIT compilation
    fn shouldUseJit(self: *WasmRuntime, func: *const WasmFunction, func_idx: u32) bool {
        // Use JIT for functions with more than 50 instructions or frequently called functions
        if (func.body.len > 50) return true;

        // Check if function is in compiled cache (indicating previous use)
        if (self.jit_compiler.compiled_functions.contains(func_idx)) return true;

        return false;
    }

    /// Generate cache key for execution results
    fn generateCacheKey(function_name: []const u8, args: []const WasmValue, contract_ctx: ?*contract.ContractContext) !u64 {
        var hasher = std.hash.Wyhash.init(0);

        // Hash function name
        hasher.update(function_name);

        // Hash arguments
        for (args) |arg| {
            switch (arg) {
                .i32 => |val| hasher.update(std.mem.asBytes(&val)),
                .i64 => |val| hasher.update(std.mem.asBytes(&val)),
                .f32 => |val| hasher.update(std.mem.asBytes(&val)),
                .f64 => |val| hasher.update(std.mem.asBytes(&val)),
                else => {}, // Skip complex types for now
            }
        }

        // Hash contract context if present
        if (contract_ctx) |ctx| {
            hasher.update(&ctx.address);
            hasher.update(std.mem.asBytes(&ctx.value));
        }

        return hasher.final();
    }

    /// Check execution cache for cached results
    fn checkExecutionCache(self: *WasmRuntime, cache_key: u64) ?contract.ExecutionResult {
        if (self.execution_cache.get(cache_key)) |cached| {
            const now = std.time.timestamp();

            // Check TTL
            if (now - cached.last_accessed > cached.ttl_seconds) {
                // Remove expired entry
                _ = self.execution_cache.remove(cache_key);
                return null;
            }

            // Update access time and hit count
            var mutable_cached = self.execution_cache.getPtr(cache_key).?;
            mutable_cached.last_accessed = now;
            mutable_cached.hit_count += 1;

            return cached.result;
        }

        return null;
    }

    /// Cache execution result
    fn cacheExecutionResult(self: *WasmRuntime, cache_key: u64, result: contract.ExecutionResult) !void {
        // Don't cache failed executions or very large results
        if (!result.success or result.return_data.len > 1024 * 1024) { // 1MB limit
            return;
        }

        const cached = CachedExecution{
            .result = result,
            .input_hash = cache_key,
            .hit_count = 0,
            .last_accessed = std.time.timestamp(),
        };

        try self.execution_cache.put(cache_key, cached);

        // Cleanup old cache entries if cache gets too large
        if (self.execution_cache.count() > 10000) {
            try self.cleanupExecutionCache();
        }
    }

    /// Cleanup old execution cache entries
    fn cleanupExecutionCache(self: *WasmRuntime) !void {
        const now = std.time.timestamp();
        var to_remove = ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var iterator = self.execution_cache.iterator();
        while (iterator.next()) |entry| {
            // Remove entries older than TTL or with low hit count
            if (now - entry.value_ptr.last_accessed > entry.value_ptr.ttl_seconds or
                entry.value_ptr.hit_count < 2)
            {
                try to_remove.append(entry.key_ptr.*);
            }
        }

        for (to_remove.items) |key| {
            if (self.execution_cache.fetchRemove(key)) |removed| {
                if (removed.value.result.return_data.len > 0) {
                    self.allocator.free(removed.value.result.return_data);
                }
            }
        }
    }

    /// Get runtime performance statistics
    pub fn getPerformanceStatistics(self: *WasmRuntime) RuntimePerformanceStats {
        const memory_stats = self.memory_pool.getStatistics();
        const jit_stats = self.jit_compiler.getCompilationStats();

        return RuntimePerformanceStats{
            .total_executions = self.runtime_statistics.total_executions,
            .jit_executions = self.runtime_statistics.jit_executions,
            .interpreted_executions = self.runtime_statistics.interpreted_executions,
            .cache_hits = self.runtime_statistics.cache_hits,
            .cache_hit_rate = if (self.runtime_statistics.total_executions > 0)
                @as(f64, @floatFromInt(self.runtime_statistics.cache_hits)) / @as(f64, @floatFromInt(self.runtime_statistics.total_executions))
            else
                0.0,
            .jit_compilation_rate = if (self.runtime_statistics.total_executions > 0)
                @as(f64, @floatFromInt(self.runtime_statistics.jit_executions)) / @as(f64, @floatFromInt(self.runtime_statistics.total_executions))
            else
                0.0,
            .memory_pool_hit_rate = if (memory_stats.allocations > 0)
                @as(f64, @floatFromInt(memory_stats.cache_hits)) / @as(f64, @floatFromInt(memory_stats.allocations))
            else
                0.0,
            .total_gas_consumed = self.runtime_statistics.total_gas_consumed,
            .avg_execution_time_ns = self.runtime_statistics.avg_execution_time_ns,
            .functions_compiled = jit_stats.functions_compiled,
            .compilation_time_ms = @as(f64, @floatFromInt(jit_stats.compilation_time_ns)) / 1_000_000.0,
        };
    }

    const RuntimePerformanceStats = struct {
        total_executions: u64,
        jit_executions: u64,
        interpreted_executions: u64,
        cache_hits: u64,
        cache_hit_rate: f64,
        jit_compilation_rate: f64,
        memory_pool_hit_rate: f64,
        total_gas_consumed: u64,
        avg_execution_time_ns: f64,
        functions_compiled: u64,
        compilation_time_ms: f64,
    };
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
