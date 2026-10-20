export function bindingTarget(platform: string, arch: string) {
  if (platform === "linux" && (arch === "x64" || arch === "arm64"))
    return {
      binary: `iroh.linux-${arch}-gnu.node`,
      library: "libnumber0_iroh.so",
      cargoTarget: undefined,
    };
  if (platform === "win32" && arch === "x64")
    return {
      binary: "iroh.win32-x64-msvc.node",
      library: "number0_iroh.dll",
      cargoTarget: "x86_64-pc-windows-msvc",
    };
  throw new Error("Iroh supports native Linux glibc and Windows x64 clients only.");
}
