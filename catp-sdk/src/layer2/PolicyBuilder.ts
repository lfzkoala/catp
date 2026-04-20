import { ActionType, AuthorizationPolicy } from "./types.js";

export class PolicyBuilder {
  private policy: Partial<AuthorizationPolicy> = {};

  allowAction(actionType: ActionType): this {
    this.policy = { ...this.policy, allowedAction: actionType };
    return this;
  }

  allowProtocol(protocol: `0x${string}`): this {
    this.policy = { ...this.policy, allowedProtocol: protocol };
    return this;
  }

  allowToken(token: `0x${string}`): this {
    this.policy = { ...this.policy, allowedToken: token };
    return this;
  }

  maxValuePerTx(value: bigint): this {
    this.policy = { ...this.policy, maxValuePerTx: value };
    return this;
  }

  maxValueTotal(value: bigint): this {
    this.policy = { ...this.policy, maxValueTotal: value };
    return this;
  }

  validFrom(timestamp: bigint): this {
    this.policy = { ...this.policy, validFrom: timestamp };
    return this;
  }

  validUntil(timestamp: bigint): this {
    this.policy = { ...this.policy, validUntil: timestamp };
    return this;
  }

  build(): AuthorizationPolicy {
    const {
      allowedAction,
      allowedProtocol,
      allowedToken,
      maxValuePerTx,
      maxValueTotal,
      validFrom,
      validUntil,
    } = this.policy;

    if (
      allowedAction === undefined ||
      allowedProtocol === undefined ||
      allowedToken === undefined ||
      maxValuePerTx === undefined ||
      maxValueTotal === undefined ||
      validFrom === undefined ||
      validUntil === undefined
    ) {
      throw new Error("PolicyBuilder: all fields are required");
    }

    return {
      allowedAction,
      allowedProtocol,
      allowedToken,
      maxValuePerTx,
      maxValueTotal,
      validFrom,
      validUntil,
    };
  }

  static encode(policy: AuthorizationPolicy): Uint8Array {
    const buf = new ArrayBuffer(8 * 8);
    const view = new DataView(buf);
    view.setUint8(0, policy.allowedAction);

    const encodeHex = (hex: string, offset: number) => {
      const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
      const padded = clean.padStart(64, "0");
      for (let i = 0; i < 32; i++) {
        view.setUint8(offset + i, parseInt(padded.slice(i * 2, i * 2 + 2), 16));
      }
    };

    encodeHex(policy.allowedProtocol, 1);
    encodeHex(policy.allowedToken, 33);

    const encodeBigInt = (value: bigint, offset: number) => {
      for (let i = 7; i >= 0; i--) {
        view.setUint8(offset + (7 - i), Number((value >> BigInt(i * 8)) & 0xffn));
      }
    };

    encodeBigInt(policy.maxValuePerTx, 65);
    encodeBigInt(policy.maxValueTotal, 73);
    encodeBigInt(policy.validFrom, 81);
    encodeBigInt(policy.validUntil, 89);

    return new Uint8Array(buf, 0, 97);
  }
}
