//! Multi-Signature Smart Contract Example
//! Demonstrates threshold signature verification using zsig integration
//! This contract requires multiple signatures to execute transactions

const std = @import("std");
const zvm = @import("zvm");

/// Multi-signature wallet contract
pub const MultiSigContract = struct {
    /// Contract configuration
    owners: []const [32]u8,  // Public keys of owners
    threshold: u32,          // Minimum signatures required
    nonce: u64,              // Transaction nonce to prevent replay attacks
    
    /// Pending transaction
    pending_transaction: ?PendingTransaction,
    
    /// Transaction proposal
    const PendingTransaction = struct {
        to: [20]u8,
        value: u64,
        data: []const u8,
        nonce: u64,
        signatures: std.ArrayList(Signature),
        
        const Signature = struct {
            signer: [32]u8,     // Public key of signer
            signature: [64]u8,  // Signature data
        };
    };
    
    pub fn init(allocator: std.mem.Allocator, owners: []const [32]u8, threshold: u32) !MultiSigContract {
        _ = allocator;
        if (threshold == 0 or threshold > owners.len) {
            return error.InvalidThreshold;
        }
        
        return MultiSigContract{
            .owners = owners,
            .threshold = threshold,
            .nonce = 0,
            .pending_transaction = null,
        };
    }
    
    /// Propose a new transaction
    pub fn proposeTransaction(self: *MultiSigContract, allocator: std.mem.Allocator, to: [20]u8, value: u64, data: []const u8) !void {
        if (self.pending_transaction != null) {
            return error.TransactionPending;
        }
        
        self.pending_transaction = PendingTransaction{
            .to = to,
            .value = value,
            .data = data,
            .nonce = self.nonce,
            .signatures = std.ArrayList(PendingTransaction.Signature).init(allocator),
        };
    }
    
    /// Sign the pending transaction
    pub fn signTransaction(self: *MultiSigContract, signer_pubkey: [32]u8, signature: [64]u8) !void {
        if (self.pending_transaction == null) {
            return error.NoTransactionPending;
        }
        
        // Verify the signer is an owner
        var is_owner = false;
        for (self.owners) |owner_pubkey| {
            if (std.mem.eql(u8, &owner_pubkey, &signer_pubkey)) {
                is_owner = true;
                break;
            }
        }
        
        if (!is_owner) {
            return error.NotAnOwner;
        }
        
        // Check if already signed
        for (self.pending_transaction.?.signatures.items) |sig| {
            if (std.mem.eql(u8, &sig.signer, &signer_pubkey)) {
                return error.AlreadySigned;
            }
        }
        
        // Add signature
        try self.pending_transaction.?.signatures.append(.{
            .signer = signer_pubkey,
            .signature = signature,
        });
        
        std.log.info("Transaction signed by owner. Signatures: {d}/{d}", .{ self.pending_transaction.?.signatures.items.len, self.threshold });
    }
    
    /// Execute the transaction if enough signatures are collected
    pub fn executeTransaction(self: *MultiSigContract) !void {
        if (self.pending_transaction == null) {
            return error.NoTransactionPending;
        }
        
        const tx = &self.pending_transaction.?;
        
        // Check if we have enough signatures
        if (tx.signatures.items.len < self.threshold) {
            return error.InsufficientSignatures;
        }
        
        // Verify all signatures (in real implementation, this would use zsig)
        for (tx.signatures.items) |sig| {
            if (!self.verifySignature(tx, sig)) {
                return error.InvalidSignature;
            }
        }
        
        // Execute the transaction
        std.log.info("Executing transaction:", .{});
        std.log.info("  To: {x}", .{tx.to});
        std.log.info("  Value: {d}", .{tx.value});
        std.log.info("  Data length: {d}", .{tx.data.len});
        
        // In real implementation, this would:
        // 1. Transfer value to recipient
        // 2. Execute contract call if data is provided
        // 3. Update contract state
        
        // Clear pending transaction and increment nonce
        self.pending_transaction.?.signatures.deinit();
        self.pending_transaction = null;
        self.nonce += 1;
        
        std.log.info("Transaction executed successfully. New nonce: {d}", .{self.nonce});
    }
    
    /// Verify a signature (mock implementation)
    fn verifySignature(self: *const MultiSigContract, tx: *const PendingTransaction, sig: PendingTransaction.Signature) bool {
        // In real implementation, this would:
        // 1. Hash the transaction data
        // 2. Use zsig to verify the signature against the hash
        // 3. Return the verification result
        
        // For this example, we'll do a simple check
        _ = self;
        _ = tx;
        _ = sig;
        
        // Mock verification - always return true for demo
        return true;
    }
    
    /// Get contract status
    pub fn getStatus(self: *const MultiSigContract) void {
        std.log.info("=== Multi-Sig Contract Status ===");
        std.log.info("Owners: {d}", .{self.owners.len});
        std.log.info("Threshold: {d}", .{self.threshold});
        std.log.info("Current nonce: {d}", .{self.nonce});
        
        if (self.pending_transaction) |tx| {
            std.log.info("Pending transaction:");
            std.log.info("  To: {x}", .{tx.to});
            std.log.info("  Value: {d}", .{tx.value});
            std.log.info("  Signatures: {d}/{d}", .{ tx.signatures.items.len, self.threshold });
        } else {
            std.log.info("No pending transaction");
        }
    }
    
    pub fn deinit(self: *MultiSigContract) void {
        if (self.pending_transaction) |*tx| {
            tx.signatures.deinit();
        }
    }
};

/// Example multi-sig contract usage
pub fn runMultiSigExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Multi-Signature Contract Example ===");
    
    // Create three owners
    const owner1 = [_]u8{0x01} ** 32;
    const owner2 = [_]u8{0x02} ** 32;
    const owner3 = [_]u8{0x03} ** 32;
    
    const owners = [_][32]u8{ owner1, owner2, owner3 };
    
    // Create 2-of-3 multi-sig contract
    var contract = try MultiSigContract.init(allocator, &owners, 2);
    defer contract.deinit();
    
    contract.getStatus();
    
    // Propose a transaction
    std.log.info("1. Proposing transaction...");
    const recipient = [_]u8{0xaa} ** 20;
    const tx_data = "Hello, Multi-Sig!";
    
    try contract.proposeTransaction(allocator, recipient, 1000, tx_data);
    contract.getStatus();
    
    // Owner 1 signs
    std.log.info("2. Owner 1 signing...");
    const sig1 = [_]u8{0x11} ** 64;
    try contract.signTransaction(owner1, sig1);
    contract.getStatus();
    
    // Try to execute with only 1 signature (should fail)
    std.log.info("3. Attempting to execute with 1 signature...");
    if (contract.executeTransaction()) {
        std.log.warn("   Transaction should not have executed!");
    } else |err| {
        std.log.info("   Execution correctly blocked: {}", .{err});
    }
    
    // Owner 2 signs
    std.log.info("4. Owner 2 signing...");
    const sig2 = [_]u8{0x22} ** 64;
    try contract.signTransaction(owner2, sig2);
    contract.getStatus();
    
    // Now execute with 2 signatures (should succeed)
    std.log.info("5. Executing with 2 signatures...");
    try contract.executeTransaction();
    contract.getStatus();
    
    std.log.info("=== Multi-Signature Contract Example Complete ===");
}

test "multi-sig contract functionality" {
    const owner1 = [_]u8{0x01} ** 32;
    const owner2 = [_]u8{0x02} ** 32;
    const owners = [_][32]u8{ owner1, owner2 };
    
    var contract = try MultiSigContract.init(std.testing.allocator, &owners, 2);
    defer contract.deinit();
    
    // Test proposing transaction
    const recipient = [_]u8{0xaa} ** 20;
    try contract.proposeTransaction(std.testing.allocator, recipient, 100, "test");
    
    // Test signing
    const sig1 = [_]u8{0x11} ** 64;
    try contract.signTransaction(owner1, sig1);
    
    // Should fail with only 1 signature
    try std.testing.expectError(error.InsufficientSignatures, contract.executeTransaction());
    
    // Add second signature
    const sig2 = [_]u8{0x22} ** 64;
    try contract.signTransaction(owner2, sig2);
    
    // Should succeed with 2 signatures
    try contract.executeTransaction();
    
    // Nonce should be incremented
    try std.testing.expect(contract.nonce == 1);
}