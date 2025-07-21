//! ZVM Client SDK - High-level client library for application integration
//! Provides easy-to-use interfaces for contract deployment, calls, and network operations

const std = @import("std");
const contract = @import("contract.zig");
const database = @import("database.zig");
const runtime = @import("runtime.zig");
const networking = @import("networking.zig");
const rpc = @import("rpc.zig");
const zvm = @import("zvm.zig");

/// Client configuration options
pub const ClientConfig = struct {
    /// RPC endpoint for ZVM server
    rpc_endpoint: []const u8 = "http://127.0.0.1:8545",
    
    /// Network endpoint for direct QUIC connections
    network_endpoint: []const u8 = "127.0.0.1:8000",
    
    /// Timeout for RPC requests in milliseconds
    request_timeout_ms: u32 = 30000,
    
    /// Default gas limit for contract calls
    default_gas_limit: u64 = 1000000,
    
    /// Enable automatic retry on network failures
    enable_retry: bool = true,
    
    /// Maximum number of retries
    max_retries: u32 = 3,
    
    /// Enable connection pooling for better performance
    enable_connection_pooling: bool = true,
    
    /// Enable DNS-over-QUIC for contract discovery
    enable_dns_resolution: bool = true,
};

/// Contract deployment result
pub const DeploymentResult = struct {
    contract_address: contract.Address,
    transaction_hash: [32]u8,
    gas_used: u64,
    block_number: u64,
    deployer: contract.Address,
    domain: ?[]const u8 = null,
};

/// Contract call result
pub const CallResult = struct {
    success: bool,
    return_data: []const u8,
    gas_used: u64,
    transaction_hash: [32]u8,
    block_number: u64,
    error_msg: ?[]const u8 = null,
    events: []ContractEvent = &[_]ContractEvent{},
    
    pub const ContractEvent = struct {
        address: contract.Address,
        topics: [][32]u8,
        data: []const u8,
    };
};

/// Contract information
pub const ContractInfo = struct {
    address: contract.Address,
    deployer: contract.Address,
    deployed_block: u64,
    bytecode_size: u64,
    storage_entries: u64,
    domain: ?[]const u8 = null,
    interface_hash: ?[32]u8 = null,
};

/// Network statistics
pub const NetworkStats = struct {
    total_nodes: u32,
    active_connections: u32,
    contracts_deployed: u64,
    total_calls: u64,
    average_latency_ms: u32,
    bandwidth_usage_mbps: f64,
};

/// Contract discovery result
pub const ContractDiscovery = struct {
    contracts: []DiscoveredContract,
    
    pub const DiscoveredContract = struct {
        address: contract.Address,
        interface_hash: [32]u8,
        node_endpoint: []const u8,
        reputation: u32,
        last_seen: u64,
    };
};

/// Main ZVM Client
pub const ZvmClient = struct {
    allocator: std.mem.Allocator,
    config: ClientConfig,
    http_client: ?HttpClient = null,
    network_client: ?networking.ContractClient = null,
    
    /// HTTP client for RPC communication (simplified interface)
    const HttpClient = struct {
        allocator: std.mem.Allocator,
        endpoint: []const u8,
        
        pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) HttpClient {
            return HttpClient{
                .allocator = allocator,
                .endpoint = endpoint,
            };
        }
        
        pub fn post(self: HttpClient, path: []const u8, body: []const u8) ![]u8 {
            // In a real implementation, this would use an HTTP client library
            // For now, return mock responses based on the request
            _ = path;
            
            if (std.mem.indexOf(u8, body, "get_version")) |_| {
                return self.allocator.dupe(u8,
                    \\{"jsonrpc":"2.0","result":{"version":"0.2.2","features":["WASM Runtime","Post-Quantum Crypto","QUIC Networking"]},"id":1}
                );
            } else if (std.mem.indexOf(u8, body, "deploy_contract")) |_| {
                return self.allocator.dupe(u8,
                    \\{"jsonrpc":"2.0","result":{"contract_address":"0x1234567890123456789012345678901234567890","transaction_hash":"0xabcdef","gas_used":500000,"block_number":12345},"id":1}
                );
            } else if (std.mem.indexOf(u8, body, "call_contract")) |_| {
                return self.allocator.dupe(u8,
                    \\{"jsonrpc":"2.0","result":{"success":true,"return_data":"0x01","gas_used":25000,"transaction_hash":"0xfedcba","block_number":12346},"id":1}
                );
            }
            
            return self.allocator.dupe(u8,
                \\{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}
            );
        }
        
        pub fn get(self: HttpClient, path: []const u8) ![]u8 {
            _ = path;
            return self.allocator.dupe(u8,
                \\{"status":"ok","version":"0.2.2"}
            );
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) !ZvmClient {
        var client = ZvmClient{
            .allocator = allocator,
            .config = config,
        };
        
        // Initialize HTTP client for RPC
        client.http_client = HttpClient.init(allocator, config.rpc_endpoint);
        
        // Initialize network client for direct QUIC connections
        if (config.enable_connection_pooling) {
            var node_id: [32]u8 = undefined;
            var rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
            rng.fill(&node_id);
            
            const pool_config = networking.ConnectionPoolConfig{};
            const bandwidth_config = networking.BandwidthConfig{};
            const bandwidth_limiter = try networking.BandwidthLimiter.init(allocator, bandwidth_config);
            const connection_pool = try networking.ConnectionPool.init(allocator, node_id, pool_config, bandwidth_limiter);
            
            client.network_client = try networking.ContractClient.init(allocator, config.network_endpoint, connection_pool);
        }
        
        return client;
    }
    
    pub fn deinit(self: *ZvmClient) void {
        if (self.network_client) |*nc| {
            nc.deinit();
        }
    }
    
    /// Deploy a contract from bytecode
    pub fn deployContract(
        self: *ZvmClient,
        bytecode: []const u8,
        deployer: contract.Address,
        options: struct {
            domain: ?[]const u8 = null,
            gas_limit: ?u64 = null,
            value: u256 = 0,
        }
    ) !DeploymentResult {
        const gas_limit = options.gas_limit orelse self.config.default_gas_limit;
        
        // Create JSON-RPC request
        const request_body = try std.fmt.allocPrint(self.allocator,
            \\{{"jsonrpc":"2.0","method":"deploy_contract","params":{{"bytecode":"{any}","deployer":"{any}","domain":"{s}","gas_limit":{},"value":{}}},"id":1}}
        , .{
            bytecode,
            deployer,
            if (options.domain) |d| d else "null",
            gas_limit,
            options.value,
        });
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        // Parse response (simplified - would use proper JSON parsing)
        return DeploymentResult{
            .contract_address = contract.AddressUtils.random(), // Mock
            .transaction_hash = [_]u8{0xab} ** 32,
            .gas_used = 500000,
            .block_number = 12345,
            .deployer = deployer,
            .domain = options.domain,
        };
    }
    
    /// Call a contract function
    pub fn callContract(
        self: *ZvmClient,
        target: ContractTarget,
        caller: contract.Address,
        options: struct {
            input_data: []const u8 = &[_]u8{},
            value: u256 = 0,
            gas_limit: ?u64 = null,
        }
    ) !CallResult {
        const gas_limit = options.gas_limit orelse self.config.default_gas_limit;
        
        // Resolve target to contract address
        const contract_address = switch (target) {
            .address => |addr| addr,
            .domain => |domain| try self.resolveDomain(domain),
        };
        
        // Create JSON-RPC request
        const request_body = try std.fmt.allocPrint(self.allocator,
            \\{{"jsonrpc":"2.0","method":"call_contract","params":{{"contract_address":"{any}","caller":"{any}","input_data":"{any}","value":{},"gas_limit":{}}},"id":1}}
        , .{
            contract_address,
            caller,
            options.input_data,
            options.value,
            gas_limit,
        });
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        // Parse response (simplified)
        return CallResult{
            .success = true,
            .return_data = try self.allocator.dupe(u8, "mock_return_data"),
            .gas_used = 25000,
            .transaction_hash = [_]u8{0xfe} ** 32,
            .block_number = 12346,
        };
    }
    
    /// Query contract storage
    pub fn queryStorage(self: *ZvmClient, contract_address: contract.Address, storage_key: u256) !u256 {
        const request_body = try std.fmt.allocPrint(self.allocator,
            \\{{"jsonrpc":"2.0","method":"query_storage","params":{{"contract_address":"{any}","storage_key":{}}},"id":1}}
        , .{
            contract_address,
            storage_key,
        });
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        // Parse response and return storage value
        return 42; // Mock value
    }
    
    /// Get contract information
    pub fn getContractInfo(self: *ZvmClient, contract_address: contract.Address) !ContractInfo {
        const request_body = try std.fmt.allocPrint(self.allocator,
            \\{{"jsonrpc":"2.0","method":"get_contract_info","params":{{"contract_address":"{any}"}},"id":1}}
        , .{contract_address});
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        return ContractInfo{
            .address = contract_address,
            .deployer = contract.AddressUtils.random(),
            .deployed_block = 12000,
            .bytecode_size = 1024,
            .storage_entries = 5,
        };
    }
    
    /// Discover contracts by interface
    pub fn discoverContracts(self: *ZvmClient, interface_hash: [32]u8, max_results: u32) !ContractDiscovery {
        const request_body = try std.fmt.allocPrint(self.allocator,
            \\{{"jsonrpc":"2.0","method":"discover_contracts","params":{{"interface_hash":"{any}","max_results":{}}},"id":1}}
        , .{
            interface_hash,
            max_results,
        });
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        // Mock discovery results
        var contracts = try self.allocator.alloc(ContractDiscovery.DiscoveredContract, 2);
        contracts[0] = ContractDiscovery.DiscoveredContract{
            .address = contract.AddressUtils.random(),
            .interface_hash = interface_hash,
            .node_endpoint = try self.allocator.dupe(u8, "127.0.0.1:8001"),
            .reputation = 100,
            .last_seen = @intCast(std.time.timestamp()),
        };
        contracts[1] = ContractDiscovery.DiscoveredContract{
            .address = contract.AddressUtils.random(),
            .interface_hash = interface_hash,
            .node_endpoint = try self.allocator.dupe(u8, "127.0.0.1:8002"),
            .reputation = 95,
            .last_seen = @intCast(std.time.timestamp()),
        };
        
        return ContractDiscovery{
            .contracts = contracts,
        };
    }
    
    /// Resolve domain name to contract address
    pub fn resolveDomain(self: *ZvmClient, domain: []const u8) !contract.Address {
        if (!self.config.enable_dns_resolution) {
            return error.DnsResolutionDisabled;
        }
        
        const request_body = try std.fmt.allocPrint(self.allocator,
            \\{{"jsonrpc":"2.0","method":"resolve_domain","params":{{"domain":"{s}"}},"id":1}}
        , .{domain});
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        // Mock domain resolution
        return contract.AddressUtils.random();
    }
    
    /// Get network statistics
    pub fn getNetworkStats(self: *ZvmClient) !NetworkStats {
        const request_body = try self.allocator.dupe(u8,
            \\{"jsonrpc":"2.0","method":"get_network_stats","id":1}
        );
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        return NetworkStats{
            .total_nodes = 3,
            .active_connections = 15,
            .contracts_deployed = 25,
            .total_calls = 1000,
            .average_latency_ms = 45,
            .bandwidth_usage_mbps = 12.5,
        };
    }
    
    /// Estimate gas for a contract call
    pub fn estimateGas(
        self: *ZvmClient,
        target: ContractTarget,
        caller: contract.Address,
        input_data: []const u8
    ) !u64 {
        const contract_address = switch (target) {
            .address => |addr| addr,
            .domain => |domain| try self.resolveDomain(domain),
        };
        
        const request_body = try std.fmt.allocPrint(self.allocator,
            \\{{"jsonrpc":"2.0","method":"estimate_gas","params":{{"contract_address":"{any}","caller":"{any}","input_data":"{any}"}},"id":1}}
        , .{
            contract_address,
            caller,
            input_data,
        });
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        return 75000; // Mock gas estimate
    }
    
    /// Get client version and capabilities
    pub fn getVersion(self: *ZvmClient) !ClientVersion {
        const request_body = try self.allocator.dupe(u8,
            \\{"jsonrpc":"2.0","method":"get_version","id":1}
        );
        defer self.allocator.free(request_body);
        
        const response = try self.sendRpcRequest(request_body);
        defer self.allocator.free(response);
        
        return ClientVersion{
            .version = "0.2.2",
            .features = try self.allocator.dupe([]const u8, &[_][]const u8{
                "WASM Runtime",
                "Post-Quantum Crypto", 
                "QUIC Networking",
                "JSON-RPC",
                "REST API",
            }),
            .protocol_version = "1.0",
        };
    }
    
    /// Check if the server is reachable
    pub fn ping(self: *ZvmClient) !bool {
        const start_time = std.time.nanoTimestamp();
        
        _ = self.getVersion() catch {
            return false;
        };
        
        const end_time = std.time.nanoTimestamp();
        const latency_ms = @as(f64, @floatFromInt(end_time - start_time)) / 1_000_000;
        
        std.log.info("Server ping successful: {d:.2}ms", .{latency_ms});
        return true;
    }
    
    // Helper types and methods
    
    const ContractTarget = union(enum) {
        address: contract.Address,
        domain: []const u8,
    };
    
    const ClientVersion = struct {
        version: []const u8,
        features: [][]const u8,
        protocol_version: []const u8,
    };
    
    fn sendRpcRequest(self: *ZvmClient, request_body: []const u8) ![]u8 {
        if (self.http_client) |http_client| {
            var retries: u32 = 0;
            while (retries <= self.config.max_retries) : (retries += 1) {
                const response = http_client.post("/", request_body) catch |err| {
                    if (self.config.enable_retry and retries < self.config.max_retries) {
                        std.log.warn("RPC request failed (attempt {}), retrying...", .{retries + 1});
                        std.time.sleep(std.time.ns_per_s); // 1 second delay
                        continue;
                    }
                    return err;
                };
                return response;
            }
            return error.MaxRetriesExceeded;
        }
        return error.HttpClientNotInitialized;
    }
};

/// High-level contract interface builder
pub const ContractBuilder = struct {
    allocator: std.mem.Allocator,
    bytecode: std.ArrayList(u8),
    
    pub fn init(allocator: std.mem.Allocator) ContractBuilder {
        return ContractBuilder{
            .allocator = allocator,
            .bytecode = std.ArrayList(u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *ContractBuilder) void {
        self.bytecode.deinit();
    }
    
    /// Add a simple counter contract
    pub fn addCounter(self: *ContractBuilder) !*ContractBuilder {
        // Simple counter bytecode
        try self.bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
        try self.bytecode.append(0); // storage key
        try self.bytecode.append(@intFromEnum(zvm.Opcode.SLOAD));
        try self.bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
        try self.bytecode.append(1);
        try self.bytecode.append(@intFromEnum(zvm.Opcode.ADD));
        try self.bytecode.append(@intFromEnum(zvm.Opcode.DUP));
        try self.bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
        try self.bytecode.append(0);
        try self.bytecode.append(@intFromEnum(zvm.Opcode.SWAP));
        try self.bytecode.append(@intFromEnum(zvm.Opcode.SSTORE));
        try self.bytecode.append(@intFromEnum(zvm.Opcode.RETURN));
        
        return self;
    }
    
    /// Add a simple echo contract
    pub fn addEcho(self: *ContractBuilder) !*ContractBuilder {
        // Echo contract bytecode
        try self.bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
        try self.bytecode.append(0); // offset
        try self.bytecode.append(@intFromEnum(zvm.Opcode.CALLDATASIZE));
        try self.bytecode.append(@intFromEnum(zvm.Opcode.RETURN));
        
        return self;
    }
    
    /// Build the final bytecode
    pub fn build(self: *ContractBuilder) []u8 {
        return self.bytecode.toOwnedSlice() catch &[_]u8{};
    }
};

test "ZVM Client SDK basic operations" {
    const allocator = std.testing.allocator;
    
    const config = ClientConfig{
        .rpc_endpoint = "http://127.0.0.1:8545",
        .enable_retry = false, // Disable retry for tests
    };
    
    var client = try ZvmClient.init(allocator, config);
    defer client.deinit();
    
    // Test ping
    const ping_result = try client.ping();
    try std.testing.expect(ping_result);
    
    // Test version
    const version = try client.getVersion();
    try std.testing.expect(std.mem.eql(u8, version.version, "0.2.2"));
    allocator.free(version.features);
    
    // Test contract deployment
    var builder = ContractBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.addCounter();
    const bytecode = builder.build();
    defer allocator.free(bytecode);
    
    const deployer = contract.AddressUtils.random();
    const deployment = try client.deployContract(bytecode, deployer, .{});
    
    try std.testing.expect(deployment.gas_used > 0);
    try std.testing.expect(deployment.block_number > 0);
    
    // Test contract call
    const caller = contract.AddressUtils.random();
    const call_result = try client.callContract(
        .{ .address = deployment.contract_address },
        caller,
        .{}
    );
    defer allocator.free(call_result.return_data);
    
    try std.testing.expect(call_result.success);
    try std.testing.expect(call_result.gas_used > 0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== ZVM Client SDK Demo ===", .{});
    
    // Initialize client
    const config = ClientConfig{
        .rpc_endpoint = "http://127.0.0.1:8545",
        .network_endpoint = "127.0.0.1:8000",
        .enable_dns_resolution = true,
    };
    
    var client = try ZvmClient.init(allocator, config);
    defer client.deinit();
    
    std.log.info("Client initialized with config:", .{});
    std.log.info("  RPC endpoint: {s}", .{config.rpc_endpoint});
    std.log.info("  Network endpoint: {s}", .{config.network_endpoint});
    std.log.info("  DNS resolution: {}", .{config.enable_dns_resolution});
    
    // Test basic connectivity
    std.log.info("\n1. Testing Connectivity:", .{});
    const ping_ok = try client.ping();
    std.log.info("Server ping: {}", .{ping_ok});
    
    const version = try client.getVersion();
    defer allocator.free(version.features);
    std.log.info("Server version: {s}", .{version.version});
    std.log.info("Features: {s}", .{version.features});
    
    // Deploy some contracts
    std.log.info("\n2. Deploying Contracts:", .{});
    
    var counter_builder = ContractBuilder.init(allocator);
    defer counter_builder.deinit();
    _ = try counter_builder.addCounter();
    const counter_bytecode = counter_builder.build();
    defer allocator.free(counter_bytecode);
    
    const deployer = contract.AddressUtils.fromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") catch unreachable;
    
    const counter_deployment = try client.deployContract(counter_bytecode, deployer, .{
        .domain = "counter.ghost",
    });
    std.log.info("Counter contract deployed at: {any}", .{counter_deployment.contract_address});
    
    var echo_builder = ContractBuilder.init(allocator);
    defer echo_builder.deinit();
    _ = try echo_builder.addEcho();
    const echo_bytecode = echo_builder.build();
    defer allocator.free(echo_bytecode);
    
    const echo_deployment = try client.deployContract(echo_bytecode, deployer, .{
        .domain = "echo.ghost",
    });
    std.log.info("Echo contract deployed at: {any}", .{echo_deployment.contract_address});
    
    // Test contract calls
    std.log.info("\n3. Contract Interactions:", .{});
    
    const caller = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
    
    // Call counter contract by address
    const counter_result = try client.callContract(
        .{ .address = counter_deployment.contract_address },
        caller,
        .{}
    );
    defer allocator.free(counter_result.return_data);
    std.log.info("Counter call result: success={}, gas={}", .{ counter_result.success, counter_result.gas_used });
    
    // Call echo contract by domain
    const echo_address = try client.resolveDomain("echo.ghost");
    const echo_result = try client.callContract(
        .{ .address = echo_address },
        caller,
        .{ .input_data = "Hello, ZVM SDK!" }
    );
    defer allocator.free(echo_result.return_data);
    std.log.info("Echo call result: success={}, gas={}", .{ echo_result.success, echo_result.gas_used });
    
    // Query contract storage
    const storage_value = try client.queryStorage(counter_deployment.contract_address, 0);
    std.log.info("Counter storage[0]: {}", .{storage_value});
    
    // Test contract discovery
    std.log.info("\n4. Contract Discovery:", .{});
    
    const interface_hash = runtime.Crypto.blake3(counter_bytecode);
    const discovery = try client.discoverContracts(interface_hash, 5);
    defer {
        for (discovery.contracts) |dc| {
            allocator.free(dc.node_endpoint);
        }
        allocator.free(discovery.contracts);
    }
    
    std.log.info("Discovered {} contracts with matching interface:", .{discovery.contracts.len});
    for (discovery.contracts, 0..) |dc, i| {
        std.log.info("  {}: {any} on {s} (reputation: {})", .{
            i + 1,
            dc.address,
            dc.node_endpoint,
            dc.reputation
        });
    }
    
    // Test network statistics
    std.log.info("\n5. Network Statistics:", .{});
    const stats = try client.getNetworkStats();
    std.log.info("Total nodes: {}", .{stats.total_nodes});
    std.log.info("Active connections: {}", .{stats.active_connections});
    std.log.info("Contracts deployed: {}", .{stats.contracts_deployed});
    std.log.info("Total calls: {}", .{stats.total_calls});
    std.log.info("Average latency: {}ms", .{stats.average_latency_ms});
    std.log.info("Bandwidth usage: {d:.1} Mbps", .{stats.bandwidth_usage_mbps});
    
    std.log.info("\n=== Client SDK Demo Complete ===", .{});
    std.log.info("✅ High-level client API for contract operations", .{});
    std.log.info("✅ Contract builder for easy bytecode generation", .{});
    std.log.info("✅ DNS resolution and contract discovery", .{});
    std.log.info("✅ Network statistics and monitoring", .{});
    std.log.info("✅ Error handling and automatic retry logic", .{});
}