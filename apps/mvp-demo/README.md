# MVP demo runtime

This process is the deployable boundary for the synthetic-data Cyber Cipher MVP. It fixes one tenant before opening database pools, probes four separately routed trust-zone databases, and exposes only liveness, readiness, and the public tenant profile. It deliberately does not proxy identified IdA traffic into the anonymous complaint boundary.

Run it through `infra/compose/docker-compose.mvp.yml`. Direct startup requires all `MVP_*` values shown in `infra/compose/.env.mvp.example` and a prior `pnpm build`.

This runtime is an integration and operations shell around the phase packages. It is not a production gateway, TLS terminator, secret manager, migration runner, or substitute for independent security review.
