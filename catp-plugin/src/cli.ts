#!/usr/bin/env node
import { createRequire } from "node:module";
import { Command } from "commander";
import { runPreHook } from "./hook/pre.js";
import { runPostHook } from "./hook/post.js";
import { cmdInit } from "./commands/init.js";
import { cmdValidate } from "./commands/validate.js";
import { cmdLogShow, cmdLogVerify } from "./commands/log.js";
import { cmdAnchor } from "./commands/anchor.js";
import { cmdWitness } from "./commands/witness.js";
import { cmdProveAuthorization, cmdVerifyAuthorization } from "./commands/authorization.js";

const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

const program = new Command();

program
  .name("catp")
  .description("CATP enforcement plugin — policy enforcement and audit for AI agents")
  .version(version);

program
  .command("init")
  .description("Scaffold a catp-policy.toml in the current directory")
  .option("--authorization", "include example authorization_groth16_v1 policy fields")
  .action(cmdInit);

program
  .command("validate")
  .description("Validate catp-policy.toml syntax")
  .option("-f, --file <path>", "path to policy file (default: auto-discover)")
  .action(cmdValidate);

const hook = program.command("hook").description("Hook handlers called by agent frameworks");

hook
  .command("pre")
  .description("PreToolUse handler — reads stdin JSON, allows or blocks")
  .action(() => { runPreHook().catch(() => process.exit(0)); });

hook
  .command("post")
  .description("PostToolUse handler — reads stdin JSON, records to audit log")
  .action(() => { runPostHook().catch(() => process.exit(0)); });

const log = program.command("log").description("Audit log commands");

log
  .command("show")
  .description("Display recent audit log entries")
  .option("-n, --lines <n>", "number of lines to show", "50")
  .option("--agent <id>", "agent id (default: from policy file)")
  .action(cmdLogShow);

log
  .command("verify")
  .description("Verify commitment chain integrity")
  .option("--agent <id>", "agent id (default: from policy file)")
  .action(cmdLogVerify);

program
  .command("anchor")
  .description("Batch audit commitments into a Merkle root and submit on-chain")
  .option("--agent <id>", "agent id (default: from policy file)")
  .option("--dry-run", "compute and print the Merkle root without submitting")
  .action(cmdAnchor);

program
  .command("witness")
  .description("Build an authorization_groth16_v1 witness from policy and action JSON")
  .option("--action <path>", "path to structured action JSON")
  .option("--audit-commitment <hex>", "build from a logged audit entry commitment")
  .option("--agent <id>", "agent id for --audit-commitment (default: from policy file)")
  .option("-f, --file <path>", "path to catp-policy.toml (default: auto-discover)")
  .option("--out <path>", "write witness JSON to file instead of stdout")
  .option("--current-timestamp <u64>", "override action currentTimestamp")
  .option("--cumulative-spend <u64>", "override action cumulativeSpend")
  .action(cmdWitness);

const prove = program.command("prove").description("Build shareable CATP proof manifests");

prove
  .command("authorization")
  .description("Build an authorization proof manifest from an artifact, action, or audit commitment")
  .option("--artifact <path>", "existing authorization_groth16_v1 proof artifact JSON")
  .option("--action <path>", "structured action JSON to prove")
  .option("--audit-commitment <hex>", "audit log commitment linked to this proof")
  .option("--agent <id>", "agent id for --audit-commitment (default: from policy file)")
  .option("-f, --file <path>", "path to catp-policy.toml (default: auto-discover)")
  .option("--current-timestamp <u64>", "override action currentTimestamp")
  .option("--cumulative-spend <u64>", "override action cumulativeSpend")
  .option("--artifact-out <path>", "keep generated proof artifact at this path")
  .option("--witness-out <path>", "keep generated witness JSON at this path")
  .option("--prover-script <path>", "Groth16 proof generation script")
  .option("--deployment <path>", "deployment metadata JSON for verifier, authorizer, and chain id")
  .option("--verifier <address>", "Groth16 authorization verifier wrapper address")
  .option("--agent-authorizer <address>", "AgentAuthorizer address")
  .option("--chain-id <id>", "chain id for the verifier/deployment")
  .option("--proof-url <url>", "external URL where proof bytes or artifact are stored")
  .option("--out <path>", "write proof manifest JSON to file instead of stdout")
  .action(cmdProveAuthorization);

const verify = program.command("verify").description("Verify CATP proof manifests");

verify
  .command("authorization")
  .description("Validate an authorization proof manifest")
  .requiredOption("--manifest <path>", "authorization proof manifest JSON")
  .option("--check-audit", "check that auditCommitment exists in the local audit log")
  .option("--audit-agent <id>", "agent id to use for --check-audit")
  .action(cmdVerifyAuthorization);

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(`catp: ${(err as Error).message}\n`);
  process.exit(1);
});
