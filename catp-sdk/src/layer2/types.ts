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
  currentTimestamp: bigint;
  cumulativeSpend: bigint;
}
