import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const composeUrl = new URL("../infra/compose/docker-compose.mvp.yml", import.meta.url);
const dockerfileUrl = new URL("../apps/mvp-demo/Dockerfile.mvp", import.meta.url);
const dockerignoreUrl = new URL("../apps/mvp-demo/.dockerignore", import.meta.url);
const [compose, dockerfile, dockerignore] = await Promise.all([
  readFile(composeUrl, "utf8"),
  readFile(dockerfileUrl, "utf8"),
  readFile(dockerignoreUrl, "utf8"),
]);

for (const zone of ["identity", "complaint", "handler", "public"]) {
  assert.match(compose, new RegExp(`^  ${zone}-db:`, "m"), `missing ${zone} trust-zone database`);
  assert.match(compose, new RegExp(`MVP_${zone.toUpperCase()}_DATABASE_URL:`), `missing ${zone} database route`);
  assert.match(compose, new RegExp(`^  ${zone}-zone: \\{ internal: true \\}`, "m"), `missing internal ${zone} network`);
}

assert.match(compose, /MVP_DATA_CLASSIFICATION: synthetic/);
assert.match(compose, /127\.0\.0\.1:\$\{MVP_PORT:-8080\}:8080/);
assert.match(compose, /read_only: true/);
assert.match(compose, /cap_drop: \[ALL\]/);
assert.match(compose, /context: \.\.\/\.\.\/apps\/mvp-demo/);
assert.match(compose, /dockerfile: Dockerfile\.mvp/);
assert.doesNotMatch(compose, /privileged:\s*true/);
assert.doesNotMatch(compose, /network_mode:\s*host/);
assert.match(dockerfile, /^USER node$/m);
assert.doesNotMatch(dockerfile, /COPY\s+\.\s+\./);
assert.match(dockerignore, /^node_modules$/m);
assert.match(dockerignore, /^dist$/m);

process.stdout.write("MVP deployment policy checks passed.\n");
