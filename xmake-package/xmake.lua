-- blook-project package manifest template for blook-kchannel.
--
-- The canonical copy lives in blook-project/blook-xmake-repo at
-- packages/b/blook-kchannel/xmake.lua; scripts/publish-registry.ps1 copies
-- this file there and appends "<version> <sha256>" to versions.txt.
--
-- Artifact contract: blook-kchannel-<version>-windows-x64.zip with
--   include/ (user + km headers), lib/x64/ (kchannel.lib, kchannel_km.lib),
--   bin/x64/ (kchannel-ctl.exe, test drivers)
package("blook-kchannel")
    set_homepage("https://github.com/blook-project/blook-kchannel")
    set_description("Kernel<->user shared-memory IPC transport (ChaCha20 + HMAC-SHA256, mapped-driver capable)")
    set_license("MIT")

    add_urls("https://github.com/blook-project/blook-kchannel/releases/download/v$(version)/blook-kchannel-$(version)-windows-x64.zip")
    add_versionfiles("versions.txt")

    on_install("windows", function (package)
        local installdir = package:installdir()
        for _, entry in ipairs({ "include", "lib", "bin", "share", "scripts" }) do
            if os.isdir(entry) then
                os.cp(entry, installdir)
            end
        end
        for _, docfile in ipairs(os.files("*.md")) do
            os.cp(docfile, installdir)
        end
        if os.isfile("LICENSE") then
            os.cp("LICENSE", installdir)
        end
    end)

    on_load(function (package)
        local installdir = package:installdir()
        if os.isdir(path.join(installdir, "include")) then
            package:add("includedirs", path.join(installdir, "include"))
        end
        for _, subdir in ipairs({ "lib/x64", "lib" }) do
            if os.isdir(path.join(installdir, subdir)) then
                package:add("linkdirs", path.join(installdir, subdir))
            end
        end
        for _, subdir in ipairs({ "bin/x64", "bin" }) do
            if os.isdir(path.join(installdir, subdir)) then
                package:add("bindirs", path.join(installdir, subdir))
            end
        end
    end)
