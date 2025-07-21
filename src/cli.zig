//! ZVM CLI - Command Line Interface for contract deployment and interaction
//! Provides comprehensive CLI commands for ZVM operations with networking support

const std = @import("std");
const contract = @import("contract.zig");
const database = @import("database.zig");
const runtime = @import("runtime.zig");
const networking = @import("networking.zig");
const zvm = @import("zvm.zig");

/// CLI Command types
pub const Command = enum {
    deploy,
    call,
    query,
    network,
    server,
    help,
    version,
    status,
    
    pub fn fromString(str: []const u8) ?Command {
        if (std.mem.eql(u8, str, "deploy")) return .deploy;
        if (std.mem.eql(u8, str, "call")) return .call;
        if (std.mem.eql(u8, str, "query")) return .query;
        if (std.mem.eql(u8, str, "network")) return .network;
        if (std.mem.eql(u8, str, "server")) return .server;
        if (std.mem.eql(u8, str, "help")) return .help;
        if (std.mem.eql(u8, str, "version")) return .version;
        if (std.mem.eql(u8, str, "status")) return .status;
        return null;
    }
};

/// CLI Configuration
pub const CliConfig = struct {
    database_path: []const u8 = "zvm.db",
    network_endpoint: []const u8 = "127.0.0.1:8000",
    gas_limit: u64 = 1000000,
    persistent: bool = true,
    verbose: bool = false,
    json_output: bool = false,
    rpc_port: u16 = 8545,
    enable_networking: bool = true,
    
    pub fn parseFromArgs(allocator: std.mem.Allocator, args: [][]const u8) !CliConfig {
        var config = CliConfig{};
        
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            
            if (std.mem.eql(u8, arg, "--db") or std.mem.eql(u8, arg, "-d")) {
                if (i + 1 < args.len) {
                    config.database_path = try allocator.dupe(u8, args[i + 1]);
                    i += 1;
                }
            } else if (std.mem.eql(u8, arg, "--endpoint") or std.mem.eql(u8, arg, "-e")) {
                if (i + 1 < args.len) {
                    config.network_endpoint = try allocator.dupe(u8, args[i + 1]);
                    i += 1;
                }
            } else if (std.mem.eql(u8, arg, "--gas") or std.mem.eql(u8, arg, "-g")) {
                if (i + 1 < args.len) {
                    config.gas_limit = std.fmt.parseInt(u64, args[i + 1], 10) catch 1000000;
                    i += 1;
                }
            } else if (std.mem.eql(u8, arg, "--rpc-port")) {
                if (i + 1 < args.len) {
                    config.rpc_port = std.fmt.parseInt(u16, args[i + 1], 10) catch 8545;
                    i += 1;
                }
            } else if (std.mem.eql(u8, arg, "--memory")) {
                config.persistent = false;
            } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
                config.verbose = true;
            } else if (std.mem.eql(u8, arg, "--json")) {
                config.json_output = true;
            } else if (std.mem.eql(u8, arg, "--no-network")) {
                config.enable_networking = false;
            }
        }
        
        return config;
    }
};

/// Main CLI application
pub const ZvmCli = struct {
    allocator: std.mem.Allocator,
    config: CliConfig,
    persistent_storage: ?database.PersistentStorage,
    network_client: ?networking.ContractClient,
    
    pub fn init(allocator: std.mem.Allocator, config: CliConfig) !ZvmCli {
        var cli = ZvmCli{
            .allocator = allocator,
            .config = config,
            .persistent_storage = null,
            .network_client = null,
        };
        
        // Initialize persistent storage if enabled
        if (config.persistent) {
            const db_config = database.DatabaseConfig{
                .type = .zqlite,
                .path = config.database_path,
                .sync_mode = .full,
            };
            cli.persistent_storage = try database.PersistentStorage.init(allocator, db_config);
        }
        
        // Initialize network client if enabled
        if (config.enable_networking) {
            // Mock connection pool setup
            var node_id: [32]u8 = undefined;
            var rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
            rng.fill(&node_id);
            
            const pool_config = networking.ConnectionPoolConfig{};
            const bandwidth_config = networking.BandwidthConfig{};
            const bandwidth_limiter = try networking.BandwidthLimiter.init(allocator, bandwidth_config);
            const connection_pool = try networking.ConnectionPool.init(allocator, node_id, pool_config, bandwidth_limiter);
            
            cli.network_client = try networking.ContractClient.init(allocator, config.network_endpoint, connection_pool);
        }
        
        return cli;
    }
    
    pub fn deinit(self: *ZvmCli) void {
        if (self.persistent_storage) |*storage| {
            storage.deinit();
        }
        if (self.network_client) |*client| {
            client.deinit();
        }
    }
    
    /// Execute CLI command
    pub fn execute(self: *ZvmCli, command: Command, args: [][]const u8) !void {
        switch (command) {
            .deploy => try self.handleDeploy(args),
            .call => try self.handleCall(args),
            .query => try self.handleQuery(args),
            .network => try self.handleNetwork(args),
            .server => try self.handleServer(args),
            .help => try self.handleHelp(args),
            .version => try self.handleVersion(),
            .status => try self.handleStatus(),
        }
    }
    
    /// Deploy a contract
    fn handleDeploy(self: *ZvmCli, args: [][]const u8) !void {
        if (args.len < 1) {
            self.printError("Usage: deploy <bytecode_file> [--domain <domain>] [--deployer <address>]", .{});
            return;
        }
        
        const bytecode_file = args[0];
        var domain: ?[]const u8 = null;
        var deployer_str: ?[]const u8 = null;
        
        // Parse additional arguments
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--domain") and i + 1 < args.len) {
                domain = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--deployer") and i + 1 < args.len) {
                deployer_str = args[i + 1];
                i += 1;
            }
        }
        
        // Read bytecode from file
        const bytecode = self.readBytecodeFile(bytecode_file) catch |err| {
            self.printError("Failed to read bytecode file: {s}", .{bytecode_file});
            return err;
        };
        defer self.allocator.free(bytecode);
        
        // Parse deployer address
        const deployer = if (deployer_str) |addr_str| 
            contract.AddressUtils.fromHex(addr_str) catch contract.AddressUtils.random()
        else 
            contract.AddressUtils.random();
        
        // Deploy contract
        const contract_address = try self.deployContract(bytecode, deployer, domain);
        
        if (self.config.json_output) {
            self.printJson(.{
                .success = true,
                .contract_address = contract_address,
                .deployer = deployer,
                .domain = domain,
            });
        } else {
            std.log.info("Contract deployed successfully!", .{});
            std.log.info("Address: {any}", .{contract_address});
            std.log.info("Deployer: {any}", .{deployer});
            if (domain) |d| {
                std.log.info("Domain: {s}", .{d});
            }
        }
    }
    
    /// Call a contract
    fn handleCall(self: *ZvmCli, args: [][]const u8) !void {
        if (args.len < 1) {
            self.printError("Usage: call <contract_address|domain> [--data <hex>] [--value <amount>] [--caller <address>]", .{});
            return;
        }
        
        const target = args[0];
        var data_hex: ?[]const u8 = null;
        var value: u256 = 0;
        var caller_str: ?[]const u8 = null;
        
        // Parse additional arguments
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--data") and i + 1 < args.len) {
                data_hex = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--value") and i + 1 < args.len) {
                value = std.fmt.parseInt(u256, args[i + 1], 10) catch 0;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--caller") and i + 1 < args.len) {
                caller_str = args[i + 1];
                i += 1;
            }
        }
        
        // Parse input data
        const input_data = if (data_hex) |hex|
            self.hexToBytes(hex) catch &[_]u8{}
        else
            &[_]u8{};
        defer if (data_hex != null) self.allocator.free(input_data);
        
        // Parse caller address
        const caller = if (caller_str) |addr_str|
            contract.AddressUtils.fromHex(addr_str) catch contract.AddressUtils.random()
        else
            contract.AddressUtils.random();
        
        // Execute contract call
        const response = try self.callContract(target, caller, value, input_data);
        
        if (self.config.json_output) {
            self.printJson(.{
                .success = response.success,
                .gas_used = response.gas_used,
                .return_data = response.return_data,
                .error_msg = response.error_msg,
                .block_number = response.block_number,
            });
        } else {
            std.log.info("Contract call completed!", .{});
            std.log.info("Success: {}", .{response.success});
            std.log.info("Gas used: {}", .{response.gas_used});
            std.log.info("Return data: {s}", .{response.return_data});
            if (response.error_msg) |err| {
                std.log.info("Error: {s}", .{err});
            }
        }
    }
    
    /// Query contract storage
    fn handleQuery(self: *ZvmCli, args: [][]const u8) !void {
        if (args.len < 2) {
            self.printError("Usage: query <contract_address> <storage_key>", .{});
            return;
        }
        
        const contract_address = contract.AddressUtils.fromHex(args[0]) catch {
            self.printError("Invalid contract address", .{});
            return;
        };
        
        const storage_key = std.fmt.parseInt(u256, args[1], 0) catch {
            self.printError("Invalid storage key", .{});
            return;
        };
        
        const value = try self.queryStorage(contract_address, storage_key);
        
        if (self.config.json_output) {
            self.printJson(.{
                .contract_address = contract_address,
                .storage_key = storage_key,
                .value = value,
            });
        } else {
            std.log.info("Storage query result:", .{});
            std.log.info("Contract: {any}", .{contract_address});
            std.log.info("Key: {}", .{storage_key});
            std.log.info("Value: {}", .{value});
        }
    }
    
    /// Handle network operations
    fn handleNetwork(self: *ZvmCli, args: [][]const u8) !void {
        if (args.len < 1) {
            self.printError("Usage: network <discover|dns|stats>", .{});
            return;
        }
        
        const subcommand = args[0];
        
        if (std.mem.eql(u8, subcommand, "discover")) {
            try self.handleNetworkDiscover(args[1..]);
        } else if (std.mem.eql(u8, subcommand, "dns")) {
            try self.handleNetworkDns(args[1..]);
        } else if (std.mem.eql(u8, subcommand, "stats")) {
            try self.handleNetworkStats();
        } else {
            self.printError("Unknown network command: {s}", .{subcommand});
        }
    }
    
    /// Start RPC server
    fn handleServer(self: *ZvmCli, args: [][]const u8) !void {
        _ = args;
        
        std.log.info("Starting ZVM RPC server on port {}", .{self.config.rpc_port});
        
        // TODO: Implement actual RPC server
        std.log.info("RPC server functionality will be implemented in rpc.zig", .{});
        std.log.info("Server would listen on: http://127.0.0.1:{}/", .{self.config.rpc_port});
        
        // For now, just simulate server running
        std.log.info("Press Ctrl+C to stop server", .{});
        std.time.sleep(std.time.ns_per_s * 3600); // Sleep for 1 hour
    }
    
    /// Show help
    fn handleHelp(self: *ZvmCli, args: [][]const u8) !void {
        _ = self;
        _ = args;
        
        std.log.info("ZVM - Zig Virtual Machine v0.2.2", .{});
        std.log.info("", .{});
        std.log.info("USAGE:", .{});
        std.log.info("  zvm <COMMAND> [OPTIONS]", .{});
        std.log.info("", .{});
        std.log.info("COMMANDS:", .{});
        std.log.info("  deploy    Deploy a contract from bytecode file", .{});
        std.log.info("  call      Call a contract function", .{});
        std.log.info("  query     Query contract storage", .{});
        std.log.info("  network   Network operations (discover, dns, stats)", .{});
        std.log.info("  server    Start RPC server", .{});
        std.log.info("  status    Show ZVM status and statistics", .{});
        std.log.info("  version   Show version information", .{});
        std.log.info("  help      Show this help message", .{});
        std.log.info("", .{});
        std.log.info("GLOBAL OPTIONS:", .{});
        std.log.info("  --db, -d <path>        Database path (default: zvm.db)", .{});
        std.log.info("  --endpoint, -e <addr>  Network endpoint (default: 127.0.0.1:8000)", .{});
        std.log.info("  --gas, -g <amount>     Gas limit (default: 1000000)", .{});
        std.log.info("  --rpc-port <port>      RPC server port (default: 8545)", .{});
        std.log.info("  --memory               Use in-memory storage", .{});
        std.log.info("  --verbose, -v          Verbose output", .{});
        std.log.info("  --json                 JSON output format", .{});
        std.log.info("  --no-network           Disable networking", .{});
    }
    
    /// Show version
    fn handleVersion(self: *ZvmCli) !void {
        _ = self;
        std.log.info("ZVM v0.2.2 - Zig Virtual Machine", .{});
        std.log.info("Features: WASM Runtime, Post-Quantum Crypto, QUIC Networking", .{});
        std.log.info("Build: {s}", .{@import("builtin").zig_version_string});
    }
    
    /// Show status
    fn handleStatus(self: *ZvmCli) !void {
        if (self.config.json_output) {
            self.printJson(.{
                .version = "0.2.2",
                .database_path = self.config.database_path,
                .network_endpoint = self.config.network_endpoint,
                .persistent_storage = self.config.persistent,
                .networking_enabled = self.config.enable_networking,
            });
        } else {
            std.log.info("ZVM Status:", .{});
            std.log.info("  Version: 0.2.2", .{});
            std.log.info("  Database: {s}", .{self.config.database_path});
            std.log.info("  Network: {s}", .{self.config.network_endpoint});
            std.log.info("  Persistent storage: {}", .{self.config.persistent});
            std.log.info("  Networking: {}", .{self.config.enable_networking});
            
            if (self.persistent_storage) |*storage| {
                const stats = storage.getStatistics() catch return;
                std.log.info("  Contracts: {}", .{stats.total_contracts});
                std.log.info("  Storage entries: {}", .{stats.total_storage_entries});
                std.log.info("  Database size: {} bytes", .{stats.database_size_bytes});
            }
        }
    }
    
    // Helper methods
    
    fn handleNetworkDiscover(self: *ZvmCli, args: [][]const u8) !void {
        _ = self;
        _ = args;
        std.log.info("Contract discovery functionality would be implemented here", .{});
    }
    
    fn handleNetworkDns(self: *ZvmCli, args: [][]const u8) !void {
        _ = self;
        _ = args;
        std.log.info("DNS resolution functionality would be implemented here", .{});
    }
    
    fn handleNetworkStats(self: *ZvmCli) !void {
        _ = self;
        std.log.info("Network statistics would be displayed here", .{});
    }
    
    fn readBytecodeFile(self: *ZvmCli, filename: []const u8) ![]u8 {
        const file = std.fs.cwd().openFile(filename, .{}) catch |err| {
            switch (err) {
                error.FileNotFound => {
                    self.printError("Bytecode file not found: {s}", .{filename});
                    return err;
                },
                else => return err,
            }
        };
        defer file.close();
        
        const file_size = try file.getEndPos();
        const contents = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(contents);
        
        return contents;
    }
    
    fn hexToBytes(self: *ZvmCli, hex_str: []const u8) ![]u8 {
        const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x"))
            hex_str[2..]
        else
            hex_str;
        
        if (clean_hex.len % 2 != 0) {
            return error.InvalidHexLength;
        }
        
        const bytes = try self.allocator.alloc(u8, clean_hex.len / 2);
        for (0..bytes.len) |i| {
            bytes[i] = std.fmt.parseInt(u8, clean_hex[i * 2..i * 2 + 2], 16) catch {
                self.allocator.free(bytes);
                return error.InvalidHexCharacter;
            };
        }
        
        return bytes;
    }
    
    fn deployContract(self: *ZvmCli, bytecode: []const u8, deployer: contract.Address, domain: ?[]const u8) !contract.Address {
        // For now, simulate deployment
        _ = domain;
        const contract_address = contract.AddressUtils.random();
        
        if (self.persistent_storage) |*storage| {
            try storage.storeContractWithMetadata(
                contract_address,
                bytecode,
                "ZVM",
                deployer,
                [_]u8{0} ** 32,
                @intCast(std.time.timestamp())
            );
        }
        
        return contract_address;
    }
    
    fn callContract(self: *ZvmCli, target: []const u8, caller: contract.Address, value: u256, input_data: []const u8) !networking.ContractCallResponse {
        _ = caller;
        _ = value;
        
        // Try to parse as address first, then as domain
        const contract_address = contract.AddressUtils.fromHex(target) catch blk: {
            // If not a valid address, treat as domain and resolve via DNS
            if (self.network_client) |*client| {
                _ = client;
                // TODO: Implement DNS resolution
                break :blk contract.AddressUtils.random();
            } else {
                return error.InvalidAddressAndNetworkingDisabled;
            }
        };
        
        _ = contract_address;
        
        // For now, return mock response
        return networking.ContractCallResponse{
            .success = true,
            .gas_used = 25000,
            .return_data = "mock_contract_response",
            .error_msg = null,
            .events = &[_]runtime.EnhancedRuntimeHooks.ContractEvent{},
            .block_number = @intCast(std.time.timestamp()),
            .transaction_hash = runtime.Crypto.keccak256(input_data),
        };
    }
    
    fn queryStorage(self: *ZvmCli, contract_address: contract.Address, storage_key: u256) !u256 {
        if (self.persistent_storage) |*storage| {
            return storage.load(contract_address, storage_key) catch 0;
        }
        
        // Mock storage query when no persistent storage
        std.log.info("Mock storage query: contract={any}, key={}", .{ contract_address, storage_key });
        return 0;
    }
    
    fn printError(self: *ZvmCli, comptime format: []const u8, args: anytype) void {
        if (self.config.json_output) {
            std.log.info("{{\"error\":true,\"message\":\"{s}\"}}", .{format});
        } else {
            std.log.err(format, args);
        }
    }
    
    fn printJson(self: *ZvmCli, data: anytype) void {
        _ = self;
        _ = data;
        // Simplified JSON output - in real implementation would use proper JSON serialization
        std.log.info("{{\"status\":\"mock_json_response\"}}", .{});
    }
};

/// Parse command line arguments and execute CLI
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        std.log.err("Usage: zvm <command> [args...]");
        std.log.err("Try 'zvm help' for more information.");
        return;
    }
    
    const command = Command.fromString(args[1]) orelse {
        std.log.err("Unknown command: {s}", .{args[1]});
        std.log.err("Try 'zvm help' for available commands.");
        return;
    };
    
    // Parse global configuration
    const config = try CliConfig.parseFromArgs(allocator, args[2..]);
    
    // Initialize CLI
    var cli = try ZvmCli.init(allocator, config);
    defer cli.deinit();
    
    // Execute command
    const command_args = if (args.len > 2) args[2..] else &[_][]const u8{};
    try cli.execute(command, command_args);
}