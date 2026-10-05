import { spawnSync } from "node:child_process";
import { packageRoot } from "./toolchain.mjs";

const result = spawnSync(process.execPath, ["--test", "--test-force-exit", "test/groth16.e2e.test.mjs"], {
  cwd: packageRoot,
  stdio: "inherit",
  env: { ...process.env, CYBER_CIPHER_ZK_PROFILE: "mvp-simulation" },
});
if (result.status !== 0) process.exit(result.status ?? 1);
