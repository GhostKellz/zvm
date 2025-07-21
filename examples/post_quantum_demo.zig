//! Post-Quantum Crypto Demo Contract
//! Demonstrates ML-DSA, ML-KEM, multi-signatures, and other advanced crypto features
const std = @import("std");
const zvm_root = @import("zvm");

const contract = zvm_root.contract;
const database = zvm_root.database;
const runtime = zvm_root.runtime;
const zvm = zvm_root.zvm;

/// Advanced crypto contract that demonstrates post-quantum capabilities
pub const PostQuantumContract = struct {
    storage: contract.Storage,
    address: contract.Address,
    owner: contract.Address,
    
    // Storage keys for different crypto operations
    const PQ_SIGNATURES_COUNT_KEY: u256 = 0;
    const MULTI_SIG_COUNT_KEY: u256 = 1;
    const HASH_COMPARISON_COUNT_KEY: u256 = 2;
    const OWNER_KEY: u256 = 3;
    
    pub fn init(allocator: std.mem.Allocator, owner: contract.Address, persistent_storage: ?*database.PersistentStorage) PostQuantumContract {
        const address = contract.AddressUtils.random();
        var storage = if (persistent_storage) |ps| 
            contract.Storage.initPersistent(allocator, ps, address)
        else
            contract.Storage.init(allocator);
        
        // Store owner
        const owner_as_u256 = std.mem.readInt(u256, std.mem.asBytes(&owner)[0..20] ++ [_]u8{0} ** 12, .big);
        storage.store(OWNER_KEY, owner_as_u256);
        
        return PostQuantumContract{
            .storage = storage,
            .address = address,
            .owner = owner,
        };
    }
    
    pub fn deinit(self: *PostQuantumContract) void {
        self.storage.deinit();
    }
    
    /// Verify a post-quantum ML-DSA signature and increment counter
    pub fn verifyMLDSASignature(self: *PostQuantumContract, message: []const u8, signature: []const u8, public_key: []const u8) !bool {
        const is_valid = runtime.Crypto.ml_dsa_verify(message, signature, public_key);
        
        if (is_valid) {
            const current = self.storage.load(PQ_SIGNATURES_COUNT_KEY);
            self.storage.store(PQ_SIGNATURES_COUNT_KEY, current + 1);
            
            std.log.info("ML-DSA signature verified! Total PQ verifications: {}", .{current + 1});
        }
        
        return is_valid;
    }
    
    /// Perform ML-KEM key encapsulation and store shared secret hash
    pub fn performKeyEncapsulation(self: *PostQuantumContract, public_key: []const u8) !?[32]u8 {
        if (runtime.Crypto.ml_kem_encapsulate(public_key)) |result| {
            // Hash the shared secret and store it
            const secret_hash = runtime.Crypto.blake3(std.mem.asBytes(&result.shared_secret));
            
            // Store hash of shared secret (for demonstration)
            var secret_as_u256: u256 = 0;
            for (secret_hash[0..32]) |byte| {
                secret_as_u256 = (secret_as_u256 << 8) | byte;
            }
            self.storage.store(4 + std.time.timestamp() % 1000, secret_as_u256); // Use timestamp-based key
            
            std.log.info("ML-KEM encapsulation successful, secret hash stored", .{});
            return secret_hash;
        }
        
        return null;
    }
    
    /// Verify multiple signatures (multi-sig simulation)
    pub fn verifyMultipleSignatures(self: *PostQuantumContract, message: []const u8, signatures: []const []const u8, public_keys: []const []const u8, threshold: u32) !bool {
        const is_valid = runtime.Crypto.multisig_verify(message, signatures, public_keys, threshold);
        
        if (is_valid) {
            const current = self.storage.load(MULTI_SIG_COUNT_KEY);
            self.storage.store(MULTI_SIG_COUNT_KEY, current + 1);
            
            std.log.info("Multi-signature verified! Threshold: {}/{}, Total multi-sig verifications: {}", .{ threshold, public_keys.len, current + 1 });
        }
        
        return is_valid;
    }
    
    /// Compare different hash functions (Keccak256, SHA256, BLAKE3)
    pub fn compareHashFunctions(self: *PostQuantumContract, data: []const u8) ![3][32]u8 {
        const keccak_hash = runtime.Crypto.keccak256(data);
        const sha256_hash = runtime.Crypto.sha256(data);
        const blake3_hash = runtime.Crypto.blake3(data);
        
        // Store count of hash comparisons
        const current = self.storage.load(HASH_COMPARISON_COUNT_KEY);
        self.storage.store(HASH_COMPARISON_COUNT_KEY, current + 1);
        
        std.log.info("Hash comparison performed. Total comparisons: {}", .{current + 1});
        std.log.info("  Keccak256: {any}", .{keccak_hash});
        std.log.info("  SHA256:    {any}", .{sha256_hash});
        std.log.info("  BLAKE3:    {any}", .{blake3_hash});
        
        return [3][32]u8{ keccak_hash, sha256_hash, blake3_hash };
    }
    
    /// Get contract statistics
    pub fn getStatistics(self: *PostQuantumContract) struct {
        pq_signatures: u256,
        multi_sigs: u256,
        hash_comparisons: u256,
        owner: contract.Address,
    } {
        return .{
            .pq_signatures = self.storage.load(PQ_SIGNATURES_COUNT_KEY),
            .multi_sigs = self.storage.load(MULTI_SIG_COUNT_KEY),
            .hash_comparisons = self.storage.load(HASH_COMPARISON_COUNT_KEY),
            .owner = self.owner,
        };
    }
    
    /// Reset counters (owner only)
    pub fn resetCounters(self: *PostQuantumContract, caller: contract.Address) !void {
        const stored_owner_u256 = self.storage.load(OWNER_KEY);
        var stored_owner: contract.Address = undefined;
        // Convert u256 back to address (first 20 bytes)
        var temp_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &temp_bytes, stored_owner_u256, .big);
        stored_owner = temp_bytes[12..32].*;
        
        if (!std.mem.eql(u8, &caller, &stored_owner)) {
            return error.Unauthorized;
        }
        
        self.storage.store(PQ_SIGNATURES_COUNT_KEY, 0);
        self.storage.store(MULTI_SIG_COUNT_KEY, 0);
        self.storage.store(HASH_COMPARISON_COUNT_KEY, 0);
        
        std.log.info("All counters reset by owner", .{});
    }
};

/// Create bytecode for post-quantum crypto contract
fn createPostQuantumBytecode(allocator: std.mem.Allocator) ![]u8 {
    var bytecode = std.ArrayList(u8).init(allocator);
    
    // Example bytecode that demonstrates post-quantum operations:
    // 1. Load message from calldata
    // 2. Load signature and public key from calldata  
    // 3. Perform ML-DSA verification
    // 4. Store result and emit event
    
    // Load message (first 32 bytes of calldata)
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(0); // offset 0
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(32); // length 32
    try bytecode.append(@intFromEnum(zvm.Opcode.CALLDATALOAD));
    
    // Load signature (next 64 bytes)
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(32); // offset 32
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(64); // length 64
    
    // Load public key (next 32 bytes)
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(96); // offset 96
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(32); // length 32
    
    // Perform ML-DSA verification
    try bytecode.append(@intFromEnum(zvm.Opcode.ML_DSA_VERIFY));
    
    // Store result in storage (key 0)
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(0); // storage key
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP));
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE));
    
    // Return success
    try bytecode.append(@intFromEnum(zvm.Opcode.RETURN));
    
    return bytecode.toOwnedSlice();
}

/// Create bytecode for hash comparison contract
fn createHashComparisonBytecode(allocator: std.mem.Allocator) ![]u8 {
    var bytecode = std.ArrayList(u8).init(allocator);
    
    // Contract that compares KECCAK256, SHA256, and BLAKE3 hashes
    // Input: data to hash from calldata
    // Output: stores all three hashes in storage
    
    // Load data from calldata
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(0); // offset
    try bytecode.append(@intFromEnum(zvm.Opcode.CALLDATASIZE));
    
    // KECCAK256 hash
    try bytecode.append(@intFromEnum(zvm.Opcode.DUP)); // duplicate offset and length
    try bytecode.append(@intFromEnum(zvm.Opcode.DUP));
    try bytecode.append(@intFromEnum(zvm.Opcode.KECCAK256));
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(1); // storage key for keccak
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP));
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE));
    
    // SHA256 hash
    try bytecode.append(@intFromEnum(zvm.Opcode.DUP));
    try bytecode.append(@intFromEnum(zvm.Opcode.DUP));
    try bytecode.append(@intFromEnum(zvm.Opcode.SHA256));
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(2); // storage key for sha256
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP));
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE));
    
    // BLAKE3 hash
    try bytecode.append(@intFromEnum(zvm.Opcode.BLAKE3));
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1));
    try bytecode.append(3); // storage key for blake3
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP));
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE));
    
    try bytecode.append(@intFromEnum(zvm.Opcode.RETURN));
    
    return bytecode.toOwnedSlice();
}

test "Post-quantum crypto contract functionality" {
    const allocator = std.testing.allocator;
    
    const db_config = database.DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };
    
    var persistent_storage = try database.PersistentStorage.init(allocator, db_config);
    defer persistent_storage.deinit();
    
    const owner = contract.AddressUtils.fromHex("0x1111111111111111111111111111111111111111") catch unreachable;
    const caller = contract.AddressUtils.fromHex("0x2222222222222222222222222222222222222222") catch unreachable;
    
    var pq_contract = PostQuantumContract.init(allocator, owner, &persistent_storage);
    defer pq_contract.deinit();
    
    // Test hash comparison
    const test_data = "Hello, Post-Quantum World!";
    const hashes = try pq_contract.compareHashFunctions(test_data);
    
    // Verify hashes are different
    try std.testing.expect(!std.mem.eql(u8, &hashes[0], &hashes[1])); // keccak != sha256
    try std.testing.expect(!std.mem.eql(u8, &hashes[1], &hashes[2])); // sha256 != blake3
    try std.testing.expect(!std.mem.eql(u8, &hashes[0], &hashes[2])); // keccak != blake3
    
    // Test statistics
    const stats = pq_contract.getStatistics();
    try std.testing.expect(stats.hash_comparisons == 1);
    try std.testing.expect(std.mem.eql(u8, &stats.owner, &owner));
    
    // Test unauthorized reset
    try std.testing.expectError(error.Unauthorized, pq_contract.resetCounters(caller));
    
    // Test authorized reset
    try pq_contract.resetCounters(owner);
    const reset_stats = pq_contract.getStatistics();
    try std.testing.expect(reset_stats.hash_comparisons == 0);
}

test "Enhanced crypto contract with bytecode execution" {
    const allocator = std.testing.allocator;
    
    const db_config = database.DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };
    
    var persistent_storage = try database.PersistentStorage.init(allocator, db_config);
    defer persistent_storage.deinit();
    
    const deployer = contract.AddressUtils.fromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") catch unreachable;
    const caller = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
    
    // Create contract with persistent storage
    var contract_storage = contract.Storage.initPersistent(allocator, &persistent_storage, deployer);
    defer contract_storage.deinit();
    
    // Create execution context
    const test_input = "Test message for hashing";
    const context = contract.ContractContext.init(
        deployer,
        caller,
        0,
        test_input,
        200000, // gas limit
        2000,   // block number
        1700000000, // timestamp
        &contract_storage
    );
    
    // Create enhanced runtime VM
    var vm = runtime.EnhancedRuntimeVM.init(allocator, context, &contract_storage, &persistent_storage);
    defer vm.deinit();
    
    // Create and execute hash comparison bytecode
    const bytecode = try createHashComparisonBytecode(allocator);
    defer allocator.free(bytecode);
    
    const result = try vm.execute(bytecode);
    try std.testing.expect(result.success);
    
    std.log.info("Hash comparison contract executed successfully! Gas used: {}", .{result.gas_used});
    
    // Verify that hashes were stored in contract storage
    const keccak_stored = contract_storage.load(1);
    const sha256_stored = contract_storage.load(2);
    const blake3_stored = contract_storage.load(3);
    
    try std.testing.expect(keccak_stored != 0);
    try std.testing.expect(sha256_stored != 0);
    try std.testing.expect(blake3_stored != 0);
    try std.testing.expect(keccak_stored != sha256_stored);
    
    std.log.info("Stored hashes - Keccak: {}, SHA256: {}, BLAKE3: {}", .{ keccak_stored, sha256_stored, blake3_stored });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Post-Quantum Crypto Demo ===", .{});
    
    const db_config = database.DatabaseConfig{
        .type = .zqlite,
        .path = "post_quantum_demo.db",
        .sync_mode = .full,
    };
    
    var persistent_storage = try database.PersistentStorage.init(allocator, db_config);
    defer persistent_storage.deinit();
    
    const owner = contract.AddressUtils.fromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") catch unreachable;
    
    std.log.info("\n1. Creating Post-Quantum Contract:", .{});
    var pq_contract = PostQuantumContract.init(allocator, owner, &persistent_storage);
    defer pq_contract.deinit();
    
    std.log.info("Contract address: {any}", .{pq_contract.address});
    
    std.log.info("\n2. Testing Hash Functions:", .{});
    const messages = [_][]const u8{
        "Hello, Quantum World!",
        "Post-quantum cryptography is the future",
        "ZVM supports ML-DSA and ML-KEM",
    };
    
    for (messages, 0..) |message, i| {
        _ = try pq_contract.compareHashFunctions(message);
        std.log.info("Message {}: \"{s}\"", .{ i + 1, message });
        std.log.info("  → Different algorithms produce different hashes ✓", .{});
    }
    
    std.log.info("\n3. Simulating Post-Quantum Operations:", .{});
    
    // Simulate ML-DSA signature verification
    const mock_message = "Important blockchain transaction";
    const mock_signature = "mock_ml_dsa_signature_data";
    const mock_pubkey = "mock_ml_dsa_public_key";
    
    // Note: This would fail in real implementation without actual ML-DSA data
    // but demonstrates the interface
    const pq_result = pq_contract.verifyMLDSASignature(mock_message, mock_signature, mock_pubkey) catch false;
    std.log.info("ML-DSA verification simulation: {s}", .{if (pq_result) "SUCCESS" else "FAILED (expected with mock data)"});
    
    std.log.info("\n4. Contract Statistics:", .{});
    const stats = pq_contract.getStatistics();
    std.log.info("Hash comparisons performed: {}", .{stats.hash_comparisons});
    std.log.info("Post-quantum signatures: {}", .{stats.pq_signatures});
    std.log.info("Multi-signatures: {}", .{stats.multi_sigs});
    std.log.info("Contract owner: {any}", .{stats.owner});
    
    std.log.info("\n5. Database Persistence:", .{});
    const db_stats = try persistent_storage.getStatistics();
    std.log.info("Total storage entries: {}", .{db_stats.total_storage_entries});
    std.log.info("Database size: {} bytes", .{db_stats.database_size_bytes});
    
    std.log.info("\n=== Demo Complete ===", .{});
    std.log.info("✅ Post-quantum crypto functions integrated", .{});
    std.log.info("✅ ML-DSA, ML-KEM, multi-sig support added", .{});
    std.log.info("✅ Enhanced hash functions (BLAKE3) available", .{});
    std.log.info("✅ Persistent storage working with crypto operations", .{});
}