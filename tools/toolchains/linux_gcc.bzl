"""C toolchain for the GCC 13 installation on the Ubuntu 24.04 workers."""

load("@rules_cc//cc:cc_toolchain_config_lib.bzl", "tool_path")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/toolchains:cc_toolchain_config_info.bzl", "CcToolchainConfigInfo")

def _linux_gcc_config_impl(ctx):
    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "linux-arm64-gcc-13",
        host_system_name = "aarch64-linux-gnu",
        target_system_name = "aarch64-linux-gnu",
        target_cpu = "aarch64",
        target_libc = "glibc",
        compiler = "gcc",
        abi_version = "gnu",
        abi_libc_version = "glibc",
        cxx_builtin_include_directories = [
            "/usr/lib/gcc/aarch64-linux-gnu/13/include",
            "/usr/local/include",
            "/usr/include/aarch64-linux-gnu",
            "/usr/include",
            "/usr/include/c++/13",
            "/usr/include/aarch64-linux-gnu/c++/13",
            "/usr/include/c++/13/backward",
        ],
        tool_paths = [
            tool_path(name = tool, path = "/usr/bin/" + tool)
            for tool in ["ar", "cpp", "dwp", "gcc", "gcov", "ld", "nm", "objcopy", "objdump", "strip"]
        ],
    )

linux_gcc_config = rule(
    implementation = _linux_gcc_config_impl,
    provides = [CcToolchainConfigInfo],
)
