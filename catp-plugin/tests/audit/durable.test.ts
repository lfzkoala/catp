import { describe, it, expect, afterEach } from "@jest/globals";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  durableAppendLine,
  durableCreateEmptyFile,
  durableWriteContentAddressed,
  ensureDirectoryDurable,
  nodeAuditStorage,
  type DurableFs,
} from "../../src/audit/durable.js";

// 0o600 === 384, 0o700 === 448. Encoding the mode in the op string lets the
// order tests also assert the required permission bits.
const MODE_FILE = 0o600;
const MODE_DIR = 0o700;

type FailPoint = "file-fsync" | "dir-fsync" | "rename";

interface FakeOptions {
  existing?: string[];
  files?: Array<[string, Buffer]>;
  partialWriteOnce?: boolean;
  zeroProgress?: boolean;
  closeThrows?: boolean;
  failOn?: FailPoint;
}

interface FakeHandle {
  fs: DurableFs;
  ops: string[];
  files: Map<string, Buffer>;
  existing: Set<string>;
  counts: () => { writes: number; fileFsync: number; dirFsync: number };
}

// A narrow in-memory filesystem that records the exact operation sequence and
// can inject a failure at a chosen durability point. Directories are opened
// with flag "r" (the only durable.ts use of "r"), so file vs directory fsync
// can be distinguished by the flag captured at open time.
function makeFakeFs(opts: FakeOptions = {}): FakeHandle {
  const existing = new Set<string>(opts.existing ?? ["/"]);
  const files = new Map<string, Buffer>(opts.files ?? []);
  const ops: string[] = [];
  const fdPath = new Map<number, string>();
  const fdFlags = new Map<number, string>();
  let nextFd = 10;
  let writes = 0;
  let fileFsync = 0;
  let dirFsync = 0;

  const err = (msg: string): Error => Object.assign(new Error(msg), { code: "EIO" });

  const fs: DurableFs = {
    existsSync: (p) => existing.has(p),
    mkdirSync: (p, o) => {
      ops.push(`mkdir:${p}:${o.mode}`);
      existing.add(p);
    },
    openSync: (p, flags, mode) => {
      const fd = nextFd++;
      fdPath.set(fd, p);
      fdFlags.set(fd, flags);
      ops.push(`open:${flags}:${mode}:${p}`);
      if (flags === "a" || flags === "w") existing.add(p);
      return fd;
    },
    writeSync: (fd, buffer, offset, length) => {
      writes++;
      if (opts.zeroProgress && writes === 1) {
        ops.push(`write-stall:${fdPath.get(fd)}`);
        return 0;
      }
      const p = fdPath.get(fd)!;
      const n = opts.partialWriteOnce && writes === 1 ? Math.min(1, length) : length;
      const chunk = Buffer.from(buffer.slice(offset, offset + n));
      files.set(p, Buffer.concat([files.get(p) ?? Buffer.alloc(0), chunk]));
      ops.push(`write:${p}:${n}`);
      return n;
    },
    fsyncSync: (fd) => {
      const p = fdPath.get(fd)!;
      const isDir = fdFlags.get(fd) === "r";
      if (isDir) {
        dirFsync++;
        if (opts.failOn === "dir-fsync") {
          ops.push(`fsync-dir-fail:${p}`);
          throw err("dir fsync failed");
        }
        ops.push(`fsync-dir:${p}`);
      } else {
        fileFsync++;
        if (opts.failOn === "file-fsync") {
          ops.push(`fsync-file-fail:${p}`);
          throw err("file fsync failed");
        }
        ops.push(`fsync-file:${p}`);
      }
    },
    closeSync: (fd) => {
      ops.push(`close:${fdPath.get(fd)}`);
      fdPath.delete(fd);
      fdFlags.delete(fd);
      if (opts.closeThrows) throw err("close failed");
    },
    readFileSync: (p) => {
      ops.push(`read:${p}`);
      const b = files.get(p);
      if (!b) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      return b;
    },
    renameSync: (o, n) => {
      if (opts.failOn === "rename") {
        ops.push(`rename-fail:${o}->${n}`);
        throw err("rename failed");
      }
      ops.push(`rename:${o}->${n}`);
      const b = files.get(o);
      files.delete(o);
      if (b) files.set(n, b);
      existing.delete(o);
      existing.add(n);
    },
    unlinkSync: (p) => {
      ops.push(`unlink:${p}`);
      files.delete(p);
      existing.delete(p);
    },
  };

  return { fs, ops, files, existing, counts: () => ({ writes, fileFsync, dirFsync }) };
}

function firstIndex(ops: string[], prefix: string): number {
  return ops.findIndex((o) => o.startsWith(prefix));
}

function lastIndex(ops: string[], prefix: string): number {
  for (let i = ops.length - 1; i >= 0; i--) if (ops[i].startsWith(prefix)) return i;
  return -1;
}

// Exact-match index. Needed for nested directory paths where one path is a
// string prefix of another (e.g. /base/a vs /base/a/b).
function exactIndex(ops: string[], op: string): number {
  return ops.indexOf(op);
}

const tmpBase = join(tmpdir(), `catp-durable-test-${Date.now()}`);
afterEach(() => {
  if (existsSync(tmpBase)) rmSync(tmpBase, { recursive: true, force: true });
});

describe("durableAppendLine (operation order)", () => {
  it("creates parents, appends line+newline, fsyncs file then parent for a new file", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp"] });
    const file = "/tmp/agent/actions.jsonl";

    durableAppendLine(file, "hello", h.fs);

    expect(h.files.get(file)?.toString("utf8")).toBe("hello\n");
    // Parent directory is created before the file is opened.
    expect(firstIndex(h.ops, "mkdir:/tmp/agent:")).toBeLessThan(firstIndex(h.ops, `open:a:${MODE_FILE}:${file}`));
    // Write happens before the file fsync, which happens before close.
    expect(firstIndex(h.ops, `write:${file}:`)).toBeLessThan(firstIndex(h.ops, `fsync-file:${file}`));
    expect(firstIndex(h.ops, `fsync-file:${file}`)).toBeLessThan(firstIndex(h.ops, `close:${file}`));
    // A newly created file fsyncs its parent directory after the file close.
    expect(lastIndex(h.ops, "fsync-dir:/tmp/agent")).toBeGreaterThan(firstIndex(h.ops, `close:${file}`));
  });

  it("opens the file with 0o600 and creates directories with 0o700", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp"] });
    durableAppendLine("/tmp/agent/actions.jsonl", "x", h.fs);
    expect(h.ops).toContain(`open:a:${MODE_FILE}:/tmp/agent/actions.jsonl`);
    expect(h.ops.some((o) => o === `mkdir:/tmp/agent:${MODE_DIR}`)).toBe(true);
  });

  it("loops until every byte is written when the first write is partial", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/agent"], partialWriteOnce: true });
    const file = "/tmp/agent/actions.jsonl";

    durableAppendLine(file, "abcdef", h.fs);

    expect(h.files.get(file)?.toString("utf8")).toBe("abcdef\n");
    expect(h.counts().writes).toBeGreaterThanOrEqual(2);
  });

  it("does not fsync the parent when appending to an existing file", () => {
    const file = "/tmp/agent/actions.jsonl";
    const h = makeFakeFs({
      existing: ["/", "/tmp", "/tmp/agent", file],
      files: [[file, Buffer.from("prior\n", "utf8")]],
    });

    durableAppendLine(file, "next", h.fs);

    expect(h.files.get(file)?.toString("utf8")).toBe("prior\nnext\n");
    expect(h.counts().dirFsync).toBe(0);
  });

  it("propagates a file-fsync failure and still closes the descriptor", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/agent"], failOn: "file-fsync" });
    const file = "/tmp/agent/actions.jsonl";

    expect(() => durableAppendLine(file, "hello", h.fs)).toThrow("file fsync failed");
    expect(h.ops).toContain(`close:${file}`);
  });

  it("propagates a directory-fsync failure", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp"], failOn: "dir-fsync" });
    expect(() => durableAppendLine("/tmp/agent/actions.jsonl", "hello", h.fs)).toThrow("dir fsync failed");
  });

  it("fails instead of spinning forever when a write makes no progress", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/agent"], zeroProgress: true });
    expect(() => durableAppendLine("/tmp/agent/actions.jsonl", "hello", h.fs)).toThrow(
      "failed to make progress",
    );
  });

  it("preserves the fsync error even when the cleanup close also fails", () => {
    const h = makeFakeFs({
      existing: ["/", "/tmp", "/tmp/agent"],
      failOn: "file-fsync",
      closeThrows: true,
    });
    // A bare finally { closeSync } would let "close failed" mask the real cause.
    expect(() => durableAppendLine("/tmp/agent/actions.jsonl", "hello", h.fs)).toThrow(
      "file fsync failed",
    );
  });
});

describe("ensureDirectoryDurable", () => {
  it("creates missing components and fsyncs deepest-upward plus the existing parent", () => {
    const h = makeFakeFs({ existing: ["/", "/base"] });

    ensureDirectoryDurable("/base/a/b", h.fs);

    expect(h.existing.has("/base/a/b")).toBe(true);
    expect(h.ops.some((o) => o === `mkdir:/base/a/b:${MODE_DIR}`)).toBe(true);
    const deep = exactIndex(h.ops, "fsync-dir:/base/a/b");
    const mid = exactIndex(h.ops, "fsync-dir:/base/a");
    const parent = exactIndex(h.ops, "fsync-dir:/base");
    expect(deep).toBeLessThan(mid);
    expect(mid).toBeLessThan(parent);
  });

  it("is a no-op when the directory already exists", () => {
    const h = makeFakeFs({ existing: ["/", "/base"] });
    ensureDirectoryDurable("/base", h.fs);
    expect(h.ops.filter((o) => o.startsWith("mkdir:") || o.startsWith("fsync-dir:"))).toHaveLength(0);
  });

  it("terminates when even the filesystem root is reported missing", () => {
    const h = makeFakeFs({ existing: [] });
    expect(() => ensureDirectoryDurable("/x", h.fs)).not.toThrow();
    expect(h.existing.has("/x")).toBe(true);
  });
});

describe("durableWriteContentAddressed", () => {
  it("writes a temp file, fsyncs it, atomically renames, then fsyncs the parent", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp"] });
    const target = "/tmp/store/deadbeef.json";
    const bytes = Buffer.from('{"x":1}', "utf8");

    durableWriteContentAddressed(target, bytes, h.fs);

    expect(h.files.get(target)?.equals(bytes)).toBe(true);
    const renameIdx = firstIndex(h.ops, `rename:`);
    expect(renameIdx).toBeGreaterThan(-1);
    expect(h.ops[renameIdx].endsWith(`->${target}`)).toBe(true);
    // File fsync precedes the rename; parent dir fsync follows it.
    expect(firstIndex(h.ops, "fsync-file:")).toBeLessThan(renameIdx);
    expect(lastIndex(h.ops, "fsync-dir:/tmp/store")).toBeGreaterThan(renameIdx);
  });

  it("opens the temp file with 0o600", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/store"] });
    durableWriteContentAddressed("/tmp/store/aa.json", Buffer.from("z", "utf8"), h.fs);
    expect(h.ops.some((o) => o.startsWith(`open:w:${MODE_FILE}:/tmp/store/.`))).toBe(true);
  });

  it("returns success without rewriting when identical bytes already exist", () => {
    const target = "/tmp/store/aa.json";
    const bytes = Buffer.from("same", "utf8");
    const h = makeFakeFs({
      existing: ["/", "/tmp", "/tmp/store", target],
      files: [[target, Buffer.from(bytes)]],
    });

    expect(() => durableWriteContentAddressed(target, bytes, h.fs)).not.toThrow();
    expect(h.ops.some((o) => o.startsWith("rename:"))).toBe(false);
    expect(h.ops.some((o) => o.startsWith("write:"))).toBe(false);
  });

  it("reports corruption when the existing target has different bytes", () => {
    const target = "/tmp/store/aa.json";
    const h = makeFakeFs({
      existing: ["/", "/tmp", "/tmp/store", target],
      files: [[target, Buffer.from("other-bytes", "utf8")]],
    });

    expect(() => durableWriteContentAddressed(target, Buffer.from("wanted", "utf8"), h.fs)).toThrow(
      /different bytes|corrupt/i,
    );
  });

  it("propagates a rename failure, closes the fd, and removes the temp file", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/store"], failOn: "rename" });

    expect(() => durableWriteContentAddressed("/tmp/store/aa.json", Buffer.from("z", "utf8"), h.fs)).toThrow(
      "rename failed",
    );
    expect(h.ops.some((o) => o.startsWith("close:"))).toBe(true);
    expect(h.ops.some((o) => o.startsWith("unlink:/tmp/store/."))).toBe(true);
  });

  it("propagates a file-fsync failure and removes the temp file", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/store"], failOn: "file-fsync" });

    expect(() => durableWriteContentAddressed("/tmp/store/aa.json", Buffer.from("z", "utf8"), h.fs)).toThrow(
      "file fsync failed",
    );
    expect(h.ops.some((o) => o.startsWith("unlink:/tmp/store/."))).toBe(true);
  });
});

describe("durableCreateEmptyFile", () => {
  it("creates parents, opens 0o600, fsyncs file then parent, and writes no bytes", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp"] });
    const file = "/tmp/agent/actions.jsonl";

    durableCreateEmptyFile(file, h.fs);

    expect(h.ops.some((o) => o === `open:a:${MODE_FILE}:${file}`)).toBe(true);
    expect(h.ops.some((o) => o.startsWith("write:"))).toBe(false);
    expect(firstIndex(h.ops, `fsync-file:${file}`)).toBeLessThan(firstIndex(h.ops, `close:${file}`));
    expect(lastIndex(h.ops, "fsync-dir:/tmp/agent")).toBeGreaterThan(firstIndex(h.ops, `close:${file}`));
  });

  it("is a no-op when the file already exists", () => {
    const file = "/tmp/agent/actions.jsonl";
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/agent", file] });

    durableCreateEmptyFile(file, h.fs);

    expect(h.ops.filter((o) => o.startsWith("open:") || o.startsWith("fsync-file:"))).toHaveLength(0);
  });

  it("propagates a file-fsync failure and still closes the descriptor", () => {
    const h = makeFakeFs({ existing: ["/", "/tmp", "/tmp/agent"], failOn: "file-fsync" });
    const file = "/tmp/agent/actions.jsonl";

    expect(() => durableCreateEmptyFile(file, h.fs)).toThrow("file fsync failed");
    expect(h.ops).toContain(`close:${file}`);
  });
});

describe("durable primitives on a real filesystem", () => {
  it("appends exact bytes with 0o600 mode", () => {
    const dir = join(tmpBase, "real-append");
    const file = join(dir, "actions.jsonl");

    durableAppendLine(file, "line1");
    durableAppendLine(file, "line2");

    expect(readFileSync(file, "utf8")).toBe("line1\nline2\n");
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it("writes a content-addressed file with exact bytes and 0o600 mode", () => {
    const dir = join(tmpBase, "real-ca");
    const file = join(dir, "beef.json");
    const bytes = Buffer.from('{"schema":"catp_tool_action_v1"}', "utf8");

    durableWriteContentAddressed(file, bytes);

    expect(readFileSync(file).equals(bytes)).toBe(true);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    // No temp files are left behind.
    expect(readFileSync(file, "utf8")).toBe(bytes.toString("utf8"));
  });

  it("is idempotent for an identical existing content-addressed file", () => {
    const dir = join(tmpBase, "real-idem");
    const file = join(dir, "aa.json");
    const bytes = Buffer.from("payload", "utf8");

    durableWriteContentAddressed(file, bytes);
    expect(() => durableWriteContentAddressed(file, bytes)).not.toThrow();
    expect(readFileSync(file).equals(bytes)).toBe(true);
  });

  it("creates nested directories durably", () => {
    const dir = join(tmpBase, "nested", "a", "b");
    ensureDirectoryDurable(dir);
    expect(statSync(dir).isDirectory()).toBe(true);
  });

  it("creates an empty 0o600 file and is idempotent", () => {
    const dir = join(tmpBase, "real-empty");
    const file = join(dir, "actions.jsonl");

    durableCreateEmptyFile(file);
    expect(statSync(file).size).toBe(0);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    // A second call leaves the existing file untouched.
    durableCreateEmptyFile(file);
    expect(statSync(file).size).toBe(0);
  });

  it("exposes the durable operations through nodeAuditStorage", () => {
    const dir = join(tmpBase, "storage");
    const file = join(dir, "actions.jsonl");
    const ca = join(dir, "ca.json");

    nodeAuditStorage.ensureDirectoryDurable(dir);
    nodeAuditStorage.createEmptyFile(file);
    nodeAuditStorage.appendLine(file, "entry");
    nodeAuditStorage.writeContentAddressed(ca, Buffer.from("v", "utf8"));

    expect(readFileSync(file, "utf8")).toBe("entry\n");
    expect(readFileSync(ca, "utf8")).toBe("v");
  });
});
