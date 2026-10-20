-- blook-kchannel build script.
--
-- User library : C++20, static lib "kchannel"
-- Kernel lib   : C++17 (/kernel), static lib "kchannel_km" via wdk.static
-- Host tests   : "kchannel-unit-tests" (gtest, no VM, no driver)
-- Guest tools  : kchannel_test.sys, kcmapload.sys, kchannel-ctl.exe
--
-- Consumers normally compile the sources into their own targets (see
-- docs/integration.md) instead of linking the prebuilt static libraries.
set_project("blook-kchannel")

-- version.txt is the release source of truth; keep this in sync (CI checks).
local version = "1.0.0"
set_version(version, {build = "%Y%m%d"})

set_languages("cxx20")
set_arch("x64")
set_defaultmode("releasedbg")
add_rules("mode.debug", "mode.releasedbg", "mode.release")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})
add_requires("gtest 1.17.0")

option("kchannel_tests")
    set_default(true)
    set_showmenu(true)
    set_description("Build host unit tests and guest tools")
option_end()

-- The WDK location is the built-in `xmake f --wdk=<root>` option; nothing to
-- declare here. Default: newest Windows Kits 10 install.
local common_files = "src/common/*.cpp"
local common_includedirs = {"include", "src"}
local version_define = "KC_ABI_VERSION_STRING=\"" .. version .. "\""

-- ---------------------------------------------------------------------------
-- User-mode library
-- ---------------------------------------------------------------------------
target("kchannel")
    set_kind("static")
    set_languages("cxx20")
    add_files("src/user/*.cpp", common_files)
    add_includedirs(common_includedirs)
    add_defines("NOMINMAX", "UNICODE", "_UNICODE", version_define)
    add_cxxflags("/utf-8", "/W4", "/permissive-", {tools = "cl"})
    add_syslinks("advapi32", "bcrypt")
    set_encodings("utf-8")

-- ---------------------------------------------------------------------------
-- Kernel-mode library (linkable into a manually mapped image)
-- ---------------------------------------------------------------------------
target("kchannel_km")
    set_kind("static")
    add_rules("wdk.static", "wdk.env.wdm")
    set_values("wdk.env.winver", "win10_vb")
    set_languages("cxx17")
    set_exceptions("no-cxx")
    add_files("src/kernel/*.cpp", common_files)
    add_includedirs(common_includedirs)
    add_defines("NOMINMAX", "POOL_NX_OPTIN=1", version_define)
    add_cxxflags("/kernel", "/GR-", "/Zc:threadSafeInit-", "/GS-",
                 "/utf-8", {force = true})
    add_syslinks("ntoskrnl", "wdmsec")
    set_encodings("utf-8")

-- ---------------------------------------------------------------------------
-- Host unit tests (no driver, no VM)
-- ---------------------------------------------------------------------------
if has_config("kchannel_tests") then
    target("kchannel-unit-tests")
        set_kind("binary")
        set_languages("cxx20")
        add_packages("gtest")
        add_files("tests/unit/*.cpp", common_files, "src/user/*.cpp")
        add_includedirs("include", "src", "tests")
        add_defines("NOMINMAX", "UNICODE", "_UNICODE", "KCHANNEL_HOST_TEST",
                    version_define)
        add_cxxflags("/utf-8", "/W4", "/permissive-", {tools = "cl"})
        add_syslinks("advapi32", "bcrypt")
        add_tests("unit")
        set_encodings("utf-8")
end

-- ---------------------------------------------------------------------------
-- Guest test driver (test-signed load and manual-map target)
-- ---------------------------------------------------------------------------
local has_guest_tools = os.isdir("tests/guest/kchannel_test")
if has_config("kchannel_tests") and has_guest_tools then
    target("kchannel_test")
        add_rules("wdk.driver", "wdk.env.wdm")
        set_values("wdk.env.winver", "win10_vb")
        set_languages("cxx17")
        set_exceptions("no-cxx")
        add_files("tests/guest/kchannel_test/*.cpp", "src/kernel/*.cpp",
                  common_files)
        add_includedirs("include", "src", "tests")
        add_defines("NOMINMAX", "POOL_NX_OPTIN=1", "KCHANNEL_TESTING")
        add_cxxflags("/kernel", "/GR-", "/Zc:threadSafeInit-",
                     "/GS-", "/utf-8", {force = true})
        add_syslinks("ntoskrnl", "wdmsec")
        add_ldflags("/INTEGRITYCHECK", "/ENTRY:DriverEntry", {force = true})
        set_encodings("utf-8")

    -- Minimal manual-map loader used by the e2e suite. Loaded test-signed
    -- through the SCM; maps kchannel_test.sys from a user-mode buffer.
    target("kcmapload")
        add_rules("wdk.driver", "wdk.env.wdm")
        set_values("wdk.env.winver", "win10_vb")
        set_languages("cxx17")
        set_exceptions("no-cxx")
        add_files("tests/guest/kcmapload/*.cpp")
        add_includedirs("include", "src")
        add_defines("NOMINMAX", "POOL_NX_OPTIN=1", "KCHANNEL_TESTING")
        add_cxxflags("/kernel", "/GR-", "/Zc:threadSafeInit-",
                     "/GS-", "/utf-8", {force = true})
        add_syslinks("ntoskrnl", "wdmsec")
        add_ldflags("/INTEGRITYCHECK", "/ENTRY:DriverEntry", {force = true})
        set_encodings("utf-8")

    -- Host-side e2e client / control tool.
    target("kchannel-ctl")
        set_kind("binary")
        set_languages("cxx20")
        add_files("tests/guest/ctl/*.cpp", "src/user/*.cpp", common_files)
        add_includedirs("include", "src", "tests")
        add_defines("NOMINMAX", "UNICODE", "_UNICODE", "KCHANNEL_TESTING")
        add_cxxflags("/utf-8", "/W4", "/permissive-", {tools = "cl"})
        add_syslinks("advapi32", "bcrypt")
        set_encodings("utf-8")
end
