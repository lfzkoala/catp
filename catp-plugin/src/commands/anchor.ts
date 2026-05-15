import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { auditRoot } from "../audit/paths.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { AuditEntry } from "../policy/types.js";

const REGISTER_POLICY_ABI = [
  {
    name: "registerPolicy",
    type: "function",
    inputs: [{ name: "policyCommitment", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

function resolveAgentId(opts: { agent?: string }): string {
  if (opts.agent) return opts.agent;
  const policyPath = findPolicyFile();
  if (policyPath) {
    try {
      return loadPolicy(policyPath).agent.id;
    } catch {
      // fall through
    }
  }
  throw new Error(
    "Could not determine agent ID. Specify --agent <id> or run from a directory with catp-policy.toml.",
  );
}

export function readCommitments(agentId: string): string[] {
  const baseDir = auditRoot(agentId);
  if (!existsSync(baseDir)) return [];

  const commitments: string[] = [];
  const dates = readdirSync(baseDir).sort();
  for (const date of dates) {
    const file = join(baseDir, date, "actions.jsonl");
    if (!existsSync(file)) continue;
    const lines = readFileSync(file, "utf8").trimEnd().split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as AuditEntry;
        if (entry.commitment) commitments.push(entry.commitment);
      } catch {
        // skip malformed lines
      }
    }
  }
  return commitments;
}

export function merkleRoot(commitments: string[]): `0x${string}` {
  if (commitments.length === 0) {
    return `0x${"00".repeat(32)}`;
  }

  let level: Buffer[] = commitments.map((c) => {
    const b = Buffer.from(c, "hex");
    return b.length === 32 ? b : createHash("sha256").update(c).digest();
  });

  while (level.length > 1) {
    if (level.length % 2 !== 0) {
      level.push(level[level.length - 1]);
    }
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        createHash("sha256").update(level[i]).update(level[i + 1]).digest(),
      );
    }
    level = next;
  }

  return `0x${level[0].toString("hex")}`;
}

async function submitOnChain(
  root: `0x${string}`,
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
): Promise<string> {
  const { createPublicClient, createWalletClient, http, defineChain } = await import("viem");
  const { privateKeyToAccount } = await import("viem/accounts");

  const publicClient = createPublicClient({ transport: http(rpcUrl) });
  const chainId = await publicClient.getChainId();

  const chain = defineChain({
    id: chainId,
    name: "catp-network",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });

  const account = privateKeyToAccount(privateKey as `0x${string}`);
  const walletClient = createWalletClient({ account, chain, transport: http(rpcUrl) });

  const hash = await walletClient.writeContract({
    address: contractAddress as `0x${string}`,
    abi: REGISTER_POLICY_ABI,
    functionName: "registerPolicy",
    args: [root],
  });

  await publicClient.waitForTransactionReceipt({ hash });
  return hash;
}

export async function cmdAnchor(opts: {
  agent?: string;
  dryRun?: boolean;
}): Promise<void> {
  const agentId = resolveAgentId(opts);
  const commitments = readCommitments(agentId);
  const root = merkleRoot(commitments);

  process.stdout.write(`Agent:       ${agentId}\n`);
  process.stdout.write(`Commitments: ${commitments.length}\n`);
  process.stdout.write(`Merkle root: ${root}\n`);

  if (commitments.length === 0) {
    process.stdout.write("No audit entries found — nothing to anchor.\n");
    return;
  }

  const rpcUrl = process.env.CATP_RPC_URL;
  const privateKey = process.env.CATP_PRIVATE_KEY;
  const contractAddress = process.env.CATP_CONTRACT_ADDRESS;

  if (opts.dryRun || !rpcUrl || !privateKey || !contractAddress) {
    if (!opts.dryRun) {
      process.stdout.write(
        "\nSet CATP_RPC_URL, CATP_PRIVATE_KEY, and CATP_CONTRACT_ADDRESS to submit on-chain.\n",
      );
    } else {
      process.stdout.write("\nDry run — skipping on-chain submission.\n");
    }
    return;
  }

  process.stdout.write("Submitting to chain...\n");
  const txHash = await submitOnChain(root, rpcUrl, privateKey, contractAddress);
  process.stdout.write(`Transaction: ${txHash}\n`);
}
