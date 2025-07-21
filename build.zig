//! Use `zig init --strip` next time to generate a project without comments.
const std = @import("std");

// Although this function looks imperative, it does not perform the build
// directly and instead it mutates the build graph (`b`) that will be then
// executed by an external runner. The functions in `std.Build` implement a DSL
// for defining build steps and express dependencies between them, allowing the
// build runner to parallelize the build automatically (and the cache system to
// know when a step doesn't need to be re-run).
pub fn build(b: *std.Build) void {
    // Standard target options allow the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});
    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});
    // Feature flags for optional dependencies
    const enable_crypto = b.option(bool, "crypto", "Enable cryptographic operations (default: true)") orelse true;
    const enable_networking = b.option(bool, "networking", "Enable networking features (default: true)") orelse true;
    const enable_wallet = b.option(bool, "wallet", "Enable wallet integration (default: true)") orelse true;
    const enable_enterprise = b.option(bool, "enterprise", "Enable enterprise features (shroud, zqlite) (default: false)") orelse false;
    const enable_persistent = b.option(bool, "persistent", "Enable persistent storage (zqlite) (default: false)") orelse false;
    
    // Core dependencies (always enabled)
    const zcrypto = if (enable_crypto) b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    
    const zsig = if (enable_crypto) b.dependency("zsig", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    
    const zquic = if (enable_networking) b.dependency("zquic", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    
    const zsync = if (enable_networking) b.dependency("zsync", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    
    const zwallet = if (enable_wallet) b.dependency("zwallet", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    
    const zns = if (enable_wallet) b.dependency("zns", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    
    // Optional enterprise dependencies
    const shroud = if (enable_enterprise) b.dependency("shroud", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    
    const zqlite = if (enable_persistent) b.dependency("zqlite", .{
        .target = target,
        .optimize = optimize,
    }) else null;

    // This creates a module, which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Zig modules are the preferred way of making Zig code available to consumers.
    // addModule defines a module that we intend to make available for importing
    // to our consumers. We must give it a name because a Zig package can expose
    // multiple modules and consumers will need to be able to specify which
    // module they want to access.
    const mod = b.addModule("zvm", .{
        // The root source file is the "entry point" of this module. Users of
        // this module will only be able to access public declarations contained
        // in this file, which means that if you have declarations that you
        // intend to expose to consumers that were defined in other files part
        // of this module, you will have to make sure to re-export them from
        // the root file.
        .root_source_file = b.path("src/root.zig"),
        // Later on we'll use this module as the root module of a test executable
        // which requires us to specify a target.
        .target = target,
    });

    // Add dependencies to the module conditionally
    if (zcrypto) |dep| mod.addImport("zcrypto", dep.module("zcrypto"));
    if (zsig) |dep| mod.addImport("zsig", dep.module("zsig"));
    if (zquic) |dep| mod.addImport("zquic", dep.module("zquic"));
    if (zsync) |dep| mod.addImport("zsync", dep.module("zsync"));
    if (zwallet) |dep| mod.addImport("zwallet", dep.module("zwallet"));
    if (zns) |dep| mod.addImport("zns", dep.module("zns"));
    if (shroud) |dep| mod.addImport("shroud", dep.module("shroud"));
    if (zqlite) |dep| mod.addImport("zqlite", dep.module("zqlite"));

    // Here we define an executable. An executable needs to have a root module
    // which needs to expose a `main` function. While we could add a main function
    // to the module defined above, it's sometimes preferable to split business
    // business logic and the CLI into two separate modules.
    //
    // If your goal is to create a Zig library for others to use, consider if
    // it might benefit from also exposing a CLI tool. A parser library for a
    // data serialization format could also bundle a CLI syntax checker, for example.
    //
    // If instead your goal is to create an executable, consider if users might
    // be interested in also being able to embed the core functionality of your
    // program in their own executable in order to avoid the overhead involved in
    // subprocessing your CLI tool.
    //
    // If neither case applies to you, feel free to delete the declaration you
    // don't need and to put everything under a single module.
    const exe = b.addExecutable(.{
        .name = "zvm",
        .root_module = b.createModule(.{
            // b.createModule defines a new module just like b.addModule but,
            // unlike b.addModule, it does not expose the module to consumers of
            // this package, which is why in this case we don't have to give it a name.
            .root_source_file = b.path("src/main.zig"),
            // Target and optimization levels must be explicitly wired in when
            // defining an executable or library (in the root module), and you
            // can also hardcode a specific target for an executable or library
            // definition if desireable (e.g. firmware for embedded devices).
            .target = target,
            .optimize = optimize,
            // List of modules available for import in source files part of the
            // root module.
            .imports = blk: {
                var imports = std.ArrayList(std.Build.Module.Import).init(b.allocator);
                imports.append(.{ .name = "zvm", .module = mod }) catch @panic("OOM");
                
                // Add conditional imports
                if (zcrypto) |dep| imports.append(.{ .name = "zcrypto", .module = dep.module("zcrypto") }) catch @panic("OOM");
                if (zsig) |dep| imports.append(.{ .name = "zsig", .module = dep.module("zsig") }) catch @panic("OOM");
                if (zquic) |dep| imports.append(.{ .name = "zquic", .module = dep.module("zquic") }) catch @panic("OOM");
                if (zsync) |dep| imports.append(.{ .name = "zsync", .module = dep.module("zsync") }) catch @panic("OOM");
                if (zwallet) |dep| imports.append(.{ .name = "zwallet", .module = dep.module("zwallet") }) catch @panic("OOM");
                if (zns) |dep| imports.append(.{ .name = "zns", .module = dep.module("zns") }) catch @panic("OOM");
                if (shroud) |dep| imports.append(.{ .name = "shroud", .module = dep.module("shroud") }) catch @panic("OOM");
                if (zqlite) |dep| imports.append(.{ .name = "zqlite", .module = dep.module("zqlite") }) catch @panic("OOM");
                
                break :blk imports.toOwnedSlice() catch @panic("OOM");
            },
        }),
    });

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    // CLI demo executable
    const cli_demo = b.addExecutable(.{
        .name = "cli_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/cli_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &[_]std.Build.Module.Import{
                .{ .name = "zvm", .module = mod },
            },
        }),
    });
    b.installArtifact(cli_demo);

    // Enhanced contract demo executable
    const enhanced_demo = b.addExecutable(.{
        .name = "enhanced_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/enhanced_contract_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &[_]std.Build.Module.Import{
                .{ .name = "zvm", .module = mod },
            },
        }),
    });
    b.installArtifact(enhanced_demo);

    // Post-quantum demo executable
    const pq_demo = b.addExecutable(.{
        .name = "pq_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/post_quantum_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &[_]std.Build.Module.Import{
                .{ .name = "zvm", .module = mod },
            },
        }),
    });
    b.installArtifact(pq_demo);

    // Networking demo executable
    const network_demo = b.addExecutable(.{
        .name = "network_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/networking_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &[_]std.Build.Module.Import{
                .{ .name = "zvm", .module = mod },
            },
        }),
    });
    b.installArtifact(network_demo);

    // This creates a top level step. Top level steps have a name and can be
    // invoked by name when running `zig build` (e.g. `zig build run`).
    // This will evaluate the `run` step rather than the default step.
    // For a top level step to actually do something, it must depend on other
    // steps (e.g. a Run step, as we will see in a moment).
    const run_step = b.step("run", "Run the app");

    // This creates a RunArtifact step in the build graph. A RunArtifact step
    // invokes an executable compiled by Zig. Steps will only be executed by the
    // runner if invoked directly by the user (in the case of top level steps)
    // or if another step depends on it, so it's up to you to define when and
    // how this Run step will be executed. In our case we want to run it when
    // the user runs `zig build run`, so we create a dependency link.
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // Demo run steps
    const run_cli_step = b.step("run-cli", "Run CLI demo");
    const run_cli_cmd = b.addRunArtifact(cli_demo);
    run_cli_step.dependOn(&run_cli_cmd.step);

    const run_enhanced_step = b.step("run-enhanced", "Run enhanced contract demo");
    const run_enhanced_cmd = b.addRunArtifact(enhanced_demo);
    run_enhanced_step.dependOn(&run_enhanced_cmd.step);

    const run_pq_step = b.step("run-pq", "Run post-quantum demo");
    const run_pq_cmd = b.addRunArtifact(pq_demo);
    run_pq_step.dependOn(&run_pq_cmd.step);

    const run_network_step = b.step("run-network", "Run networking demo");
    const run_network_cmd = b.addRunArtifact(network_demo);
    run_network_step.dependOn(&run_network_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Creates an executable that will run `test` blocks from the provided module.
    // Here `mod` needs to define a target, which is why earlier we made sure to
    // set the releative field.
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    // A run step that will run the test executable.
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Creates an executable that will run `test` blocks from the executable's
    // root module. Note that test executables only test one module at a time,
    // hence why we have to create two separate ones.
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    // A run step that will run the second test executable.
    const run_exe_tests = b.addRunArtifact(exe_tests);

    // A top level step for running all tests. dependOn can be called multiple
    // times and since the two run steps do not depend on one another, this will
    // make the two of them run in parallel.
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // Just like flags, top level steps are also listed in the `--help` menu.
    //
    // The Zig build system is entirely implemented in userland, which means
    // that it cannot hook into private compiler APIs. All compilation work
    // orchestrated by the build system will result in other Zig compiler
    // subcommands being invoked with the right flags defined. You can observe
    // these invocations when one fails (or you pass a flag to increase
    // verbosity) to validate assumptions and diagnose problems.
    //
    // Lastly, the Zig build system is relatively simple and self-contained,
    // and reading its source code will allow you to master it.
}
