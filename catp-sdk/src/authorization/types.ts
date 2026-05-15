export enum ActionType {
  Swap = 0,
  Transfer = 1,
  Deposit = 2,
  Withdraw = 3,
}

export interface Action {
  actionType: ActionType;
  protocol: `0x${string}`;
  token: `0x${string}`;
  value: bigint;
}

export interface AuthorizationPolicy {
  allowedAction: ActionType;
  allowedProtocol: `0x${string}`;
  allowedToken: `0x${string}`;
  maxValuePerTx: bigint;
  maxValueTotal: bigint;
  validFrom: bigint;
  validUntil: bigint;
}

export interface AuthorizationPublicInputs {
  policyCommitment: `0x${string}`;
  actionType: bigint;
  actionProtocol: [bigint, bigint, bigint, bigint];
  actionToken: [bigint, bigint, bigint, bigint];
  actionValue: bigint;
  currentTimestamp: bigint;
  cumulativeSpend: bigint;
}

export interface Groth16AuthorizationProofArtifact {
  proofVersion: "authorization_groth16_v1";
  policyCommitment: `0x${string}`;
  publicInputs: [
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
    `0x${string}`,
  ];
  actionData: `0x${string}`;
  currentTimestamp: number | bigint | string;
  cumulativeSpend: number | bigint | string;
  value: number | bigint | string;
  proof: `0x${string}`;
  constraintCount: number;
}

export interface Groth16AuthorizationCall {
  proofVersion: "authorization_groth16_v1";
  policyCommitment: `0x${string}`;
  actionData: `0x${string}`;
  currentTimestamp: bigint;
  proof: `0x${string}`;
  publicInputs: AuthorizationPublicInputs;
}
