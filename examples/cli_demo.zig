//! CLI/RPC/Client Integration Demo
//! Demonstrates the complete CLI, RPC server, and client SDK integration

const std = @import("std");
const zvm = @import("zvm");

const contract = zvm.contract;
const database = zvm.database;
const runtime = zvm.runtime;
const networking = zvm.networking;
const cli = zvm.cli;
const rpc = zvm.rpc;
const client = zvm.client;

/// Comprehensive demo environment
pub const DemoEnvironment = struct {
    allocator: std.mem.Allocator,
    rpc_server: rpc.RpcServer,
    client_sdk: client.ZvmClient,
    running: bool = false,
    
    pub fn init(allocator: std.mem.Allocator) !DemoEnvironment {
        // Initialize RPC server
        const rpc_config = rpc.RpcConfig{
            .bind_address = "127.0.0.1",
            .port = 8545,
            .database_path = "cli_demo.db",
            .enable_networking = true,
        };
        
        const rpc_server = try rpc.RpcServer.init(allocator, rpc_config);
        
        // Initialize client SDK
        const client_config = client.ClientConfig{
            .rpc_endpoint = "http://127.0.0.1:8545",
            .network_endpoint = "127.0.0.1:8000",
            .enable_dns_resolution = true,
            .enable_retry = false, // Disable for demo
        };
        
        const client_sdk = try client.ZvmClient.init(allocator, client_config);
        
        return DemoEnvironment{
            .allocator = allocator,
            .rpc_server = rpc_server,
            .client_sdk = client_sdk,
        };
    }
    
    pub fn deinit(self: *DemoEnvironment) void {
        self.rpc_server.deinit();
        self.client_sdk.deinit();
    }
    
    /// Run comprehensive demo
    pub fn runDemo(self: *DemoEnvironment) !void {
        std.log.info("=== ZVM CLI/RPC/Client Integration Demo ===", .{});
        
        try self.demoCliInterface();
        try self.demoRpcServer();
        try self.demoClientSdk();
        try self.demoIntegration();
        
        std.log.info("\n=== Demo Complete ===", .{});
    }
    
    /// Demonstrate CLI interface
    fn demoCliInterface(self: *DemoEnvironment) !void {
        std.log.info("\n1. CLI Interface Demo:", .{});
        
        // Create CLI configuration
        const cli_config = cli.CliConfig{
            .database_path = "cli_demo.db",
            .network_endpoint = "127.0.0.1:8000",
            .gas_limit = 1000000,
            .persistent = true,
            .verbose = true,
            .json_output = false,
            .enable_networking = true,
        };
        
        var zvm_cli = try cli.ZvmCli.init(self.allocator, cli_config);
        defer zvm_cli.deinit();
        
        std.log.info("CLI initialized with config:", .{});
        std.log.info("  Database: {s}", .{cli_config.database_path});
        std.log.info("  Network: {s}", .{cli_config.network_endpoint});
        std.log.info("  Gas limit: {}", .{cli_config.gas_limit});
        
        // Simulate CLI commands
        std.log.info("\nSimulating CLI commands:", .{});
        
        // zvm version
        std.log.info("$ zvm version", .{});
        try zvm_cli.execute(.version, &[_][]const u8{});
        
        // zvm status
        std.log.info("\n$ zvm status", .{});
        try zvm_cli.execute(.status, &[_][]const u8{});
        
        // zvm help
        std.log.info("\n$ zvm help", .{});
        try zvm_cli.execute(.help, &[_][]const u8{});
    }
    
    /// Demonstrate RPC server functionality
    fn demoRpcServer(self: *DemoEnvironment) !void {
        std.log.info("\n2. RPC Server Demo:", .{});
        
        std.log.info("RPC server configuration:", .{});
        std.log.info("  Bind address: 127.0.0.1:8545", .{});
        std.log.info("  JSON-RPC endpoint: http://127.0.0.1:8545/", .{});
        std.log.info("  REST API endpoint: http://127.0.0.1:8545/api/", .{});
        
        // Simulate HTTP requests
        std.log.info("\nSimulating API requests:", .{});
        
        // JSON-RPC request
        var rpc_request = rpc.HttpRequest.init(self.allocator);
        defer rpc_request.deinit();
        
        rpc_request.method = "POST";
        rpc_request.path = "/";
        rpc_request.body = 
            \\{"jsonrpc":"2.0","method":"get_version","id":1}
        ;
        
        var rpc_response = try self.rpc_server.handleRequest(rpc_request);
        defer rpc_response.deinit();
        
        std.log.info("JSON-RPC get_version response:", .{});
        std.log.info("  Status: {}", .{rpc_response.status_code});
        std.log.info("  Body: {s}", .{rpc_response.body});
        
        // REST API request
        rpc_request.method = "GET";
        rpc_request.path = "/api/status";
        rpc_request.body = "";
        
        var rest_response = try self.rpc_server.handleRequest(rpc_request);
        defer rest_response.deinit();
        
        std.log.info("\nREST API /api/status response:", .{});
        std.log.info("  Status: {}", .{rest_response.status_code});
        std.log.info("  Body: {s}", .{rest_response.body});
        
        // Contract deployment via RPC
        rpc_request.method = "POST";
        rpc_request.path = "/";
        rpc_request.body = 
            \\{"jsonrpc":"2.0","method":"deploy_contract","params":{"bytecode":"608060405234801561001057600080fd5b50","deployer":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},"id":1}
        ;
        
        var deploy_response = try self.rpc_server.handleRequest(rpc_request);
        defer deploy_response.deinit();
        
        std.log.info("\nContract deployment response:", .{});
        std.log.info("  Status: {}", .{deploy_response.status_code});
        std.log.info("  Body: {s}", .{deploy_response.body});
    }
    
    /// Demonstrate client SDK functionality
    fn demoClientSdk(self: *DemoEnvironment) !void {
        std.log.info("\n3. Client SDK Demo:", .{});
        
        // Test connectivity
        const ping_ok = try self.client_sdk.ping();
        std.log.info("Server connectivity: {}", .{ping_ok});
        
        // Get version
        const version = try self.client_sdk.getVersion();
        defer self.allocator.free(version.features);
        std.log.info("Server version: {s}", .{version.version});
        std.log.info("Protocol version: {s}", .{version.protocol_version});
        
        // Build and deploy contracts
        var counter_builder = client.ContractBuilder.init(self.allocator);
        defer counter_builder.deinit();
        _ = try counter_builder.addCounter();
        const counter_bytecode = counter_builder.build();
        defer self.allocator.free(counter_bytecode);
        
        var echo_builder = client.ContractBuilder.init(self.allocator);
        defer echo_builder.deinit();
        _ = try echo_builder.addEcho();
        const echo_bytecode = echo_builder.build();
        defer self.allocator.free(echo_bytecode);
        
        const deployer = contract.AddressUtils.fromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") catch unreachable;
        
        // Deploy counter contract
        const counter_deployment = try self.client_sdk.deployContract(counter_bytecode, deployer, .{
            .domain = "counter.ghost",
        });
        std.log.info("Counter deployed: {x}", .{counter_deployment.contract_address});
        std.log.info("  Gas used: {}", .{counter_deployment.gas_used});
        std.log.info("  Block: {}", .{counter_deployment.block_number});
        
        // Deploy echo contract
        const echo_deployment = try self.client_sdk.deployContract(echo_bytecode, deployer, .{
            .domain = "echo.ghost",
        });
        std.log.info("Echo deployed: {x}", .{echo_deployment.contract_address});
        
        // Contract interactions
        const caller = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
        
        // Call counter multiple times
        for (0..3) |i| {
            const counter_result = try self.client_sdk.callContract(
                .{ .address = counter_deployment.contract_address },
                caller,
                .{}
            );
            defer self.allocator.free(counter_result.return_data);
            
            std.log.info("Counter call {}: gas={}, success={}", .{ i + 1, counter_result.gas_used, counter_result.success });
        }
        
        // Query storage
        const storage_value = try self.client_sdk.queryStorage(counter_deployment.contract_address, 0);
        std.log.info("Counter storage[0]: {}", .{storage_value});
        
        // Test gas estimation
        const gas_estimate = try self.client_sdk.estimateGas(
            .{ .address = echo_deployment.contract_address },
            caller,
            "Hello, ZVM!"
        );
        std.log.info("Gas estimate for echo call: {}", .{gas_estimate});
        
        // Contract discovery
        const interface_hash = runtime.Crypto.blake3(counter_bytecode);
        const discovery = try self.client_sdk.discoverContracts(interface_hash, 5);
        defer {
            for (discovery.contracts) |dc| {
                self.allocator.free(dc.node_endpoint);
            }
            self.allocator.free(discovery.contracts);
        }
        
        std.log.info("Discovered {} contracts:", .{discovery.contracts.len});
        for (discovery.contracts, 0..) |dc, i| {
            std.log.info("  {}: {any} (reputation: {})", .{
                i + 1,
                dc.address,
                dc.reputation
            });
        }
    }
    
    /// Demonstrate full integration
    fn demoIntegration(self: *DemoEnvironment) !void {
        std.log.info("\n4. Full Integration Demo:", .{});
        
        // Create a complex workflow using all components
        std.log.info("Simulating complex workflow:", .{});
        
        // 1. Deploy contract via CLI-style operation
        std.log.info("1. Deploy contract via CLI-style operation", .{});
        var builder = client.ContractBuilder.init(self.allocator);
        defer builder.deinit();
        _ = try builder.addCounter();
        const bytecode = builder.build();
        defer self.allocator.free(bytecode);
        
        const deployer = contract.AddressUtils.random();
        const deployment = try self.client_sdk.deployContract(bytecode, deployer, .{
            .domain = "workflow.ghost",
            .gas_limit = 800000,
        });
        
        // 2. Query contract info via RPC
        std.log.info("2. Query contract info via RPC", .{});
        const contract_info = try self.client_sdk.getContractInfo(deployment.contract_address);
        std.log.info("  Deployer: {x}", .{contract_info.deployer});
        std.log.info("  Deployed block: {}", .{contract_info.deployed_block});
        std.log.info("  Bytecode size: {}", .{contract_info.bytecode_size});
        
        // 3. Perform multiple operations
        std.log.info("3. Perform multiple operations", .{});
        const caller = contract.AddressUtils.random();
        
        for (0..5) |i| {
            // Call contract
            const result = try self.client_sdk.callContract(
                .{ .address = deployment.contract_address },
                caller,
                .{}
            );
            defer self.allocator.free(result.return_data);
            
            // Query storage
            const value = try self.client_sdk.queryStorage(deployment.contract_address, 0);
            
            std.log.info("  Operation {}: gas={}, storage[0]={}", .{ i + 1, result.gas_used, value });
        }
        
        // 4. Get network statistics
        std.log.info("4. Network statistics", .{});
        const stats = try self.client_sdk.getNetworkStats();
        std.log.info("  Total calls: {}", .{stats.total_calls});
        std.log.info("  Average latency: {}ms", .{stats.average_latency_ms});
        std.log.info("  Bandwidth: {d:.1} Mbps", .{stats.bandwidth_usage_mbps});
        
        // 5. Domain resolution
        std.log.info("5. Domain resolution", .{});
        const resolved_address = try self.client_sdk.resolveDomain("workflow.ghost");
        std.log.info("  workflow.ghost -> {x}", .{resolved_address});
        
        std.log.info("Workflow completed successfully!", .{});
    }
};

/// Example of CLI command parsing and execution
fn demonstrateCliParsing(allocator: std.mem.Allocator) !void {
    std.log.info("\n5. CLI Command Parsing Demo:", .{});
    
    // Simulate various CLI commands
    const commands = [_][]const []const u8{
        &[_][]const u8{ "zvm", "version" },
        &[_][]const u8{ "zvm", "deploy", "counter.bin", "--domain", "test.ghost" },
        &[_][]const u8{ "zvm", "call", "0x1234567890123456789012345678901234567890", "--data", "0x01020304" },
        &[_][]const u8{ "zvm", "query", "0x1234567890123456789012345678901234567890", "0" },
        &[_][]const u8{ "zvm", "network", "stats" },
        &[_][]const u8{ "zvm", "server", "--rpc-port", "8080" },
    };
    
    for (commands) |cmd_args| {
        std.log.info("$ {s}", .{std.mem.join(allocator, " ", cmd_args) catch "command"});
        
        if (cmd_args.len > 1) {
            const command = cli.Command.fromString(cmd_args[1]) orelse {
                std.log.info("  Unknown command", .{});
                continue;
            };
            
            switch (command) {
                .version => std.log.info("  -> Shows ZVM version 0.2.2", .{}),
                .deploy => std.log.info("  -> Deploys contract from bytecode file", .{}),
                .call => std.log.info("  -> Calls contract function", .{}),
                .query => std.log.info("  -> Queries contract storage", .{}),
                .network => std.log.info("  -> Shows network statistics", .{}),
                .server => std.log.info("  -> Starts RPC server on specified port", .{}),
                else => std.log.info("  -> Executes {} command", .{command}),
            }
        }
    }
}

/// Example RPC method implementations
fn demonstrateRpcMethods(_: std.mem.Allocator) !void {
    std.log.info("\n6. RPC Methods Demo:", .{});
    
    const rpc_methods = [_][]const u8{
        "deploy_contract",
        "call_contract", 
        "query_storage",
        "get_contract_info",
        "discover_contracts",
        "resolve_domain",
        "get_network_stats",
        "get_version",
        "get_status",
        "estimate_gas",
    };
    
    std.log.info("Available RPC methods:", .{});
    for (rpc_methods, 0..) |method, i| {
        const rpc_method = rpc.RpcMethod.fromString(method);
        std.log.info("  {}: {s} -> {any}", .{ i + 1, method, rpc_method });
    }
    
    // Example JSON-RPC requests
    const example_requests = [_][]const u8{
        \\{"jsonrpc":"2.0","method":"get_version","id":1}
        ,
        \\{"jsonrpc":"2.0","method":"deploy_contract","params":{"bytecode":"0x608060405234801561001057600080fd5b50","deployer":"0xdeadbeef"},"id":2}
        ,
        \\{"jsonrpc":"2.0","method":"call_contract","params":{"contract_address":"0x1234567890","caller":"0xabcdef","input_data":"0x"},"id":3}
        ,
    };
    
    std.log.info("\nExample JSON-RPC requests:", .{});
    for (example_requests, 0..) |request, i| {
        std.log.info("  {}: {s}", .{ i + 1, request });
    }
}

test "CLI/RPC/Client integration test" {
    const allocator = std.testing.allocator;
    
    // Test CLI config parsing
    const args = [_][]const u8{ "--db", "test.db", "--gas", "500000", "--verbose" };
    const config = try cli.CliConfig.parseFromArgs(allocator, &args);
    
    try std.testing.expect(config.gas_limit == 500000);
    try std.testing.expect(config.verbose == true);
    
    // Test RPC method parsing
    const method = rpc.RpcMethod.fromString("deploy_contract");
    try std.testing.expect(method == .deploy_contract);
    
    // Test client SDK initialization
    const client_config = client.ClientConfig{
        .rpc_endpoint = "http://127.0.0.1:8545",
        .enable_retry = false,
    };
    
    var zvm_client = try client.ZvmClient.init(allocator, client_config);
    defer zvm_client.deinit();
    
    // Test contract builder
    var builder = client.ContractBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.addCounter();
    const bytecode = builder.build();
    defer allocator.free(bytecode);
    
    try std.testing.expect(bytecode.len > 0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize demo environment
    var demo = try DemoEnvironment.init(allocator);
    defer demo.deinit();
    
    // Run comprehensive demo
    try demo.runDemo();
    
    // Additional demonstrations
    try demonstrateCliParsing(allocator);
    try demonstrateRpcMethods(allocator);
    
    std.log.info("\n=== CLI/RPC/Client Integration Complete ===", .{});
    std.log.info("✅ Command-line interface with full command support", .{});
    std.log.info("✅ JSON-RPC 2.0 server with comprehensive API", .{});
    std.log.info("✅ REST API endpoints for web integration", .{});
    std.log.info("✅ High-level client SDK for application developers", .{});
    std.log.info("✅ Contract builder for easy bytecode generation", .{});
    std.log.info("✅ DNS resolution and contract discovery", .{});
    std.log.info("✅ Network statistics and monitoring", .{});
    std.log.info("✅ Complete integration between all components", .{});
}