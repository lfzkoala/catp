import {
  closeSync,
  existsSync,
  fsyncSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

/**
 * Narrow filesystem seam used by the durable primitives. Production code binds
 * this to node:fs; unit tests inject a fake to assert operation order and to
 * inject failures without touching a real disk.
 */
export interface DurableFs {
  existsSync(path: string): boolean;
  mkdirSync(path: string, opts: { recursive: boolean; mode: number }): void;
  openSync(path: string, flags: string, mode: number): number;
  writeSync(
    fd: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | null,
  ): number;
  fsyncSync(fd: number): void;
  closeSync(fd: number): void;
  readFileSync(path: string): Buffer;
  renameSync(oldPath: string, newPath: string): void;
  unlinkSync(path: string): void;
  /** Size of a file in bytes, used to record the pre-append rollback point. */
  statSync(path: string): { size: number };
  /** Truncate an open file to `len` bytes, used to roll back a torn append. */
  ftruncateSync(fd: number, len: number): void;
}

/** Production binding of {@link DurableFs} to node:fs. */
export const nodeFs: DurableFs = {
  existsSync: (p) => existsSync(p),
  mkdirSync: (p, opts) => {
    mkdirSync(p, opts);
  },
  openSync: (p, flags, mode) => openSync(p, flags, mode),
  writeSync: (fd, buffer, offset, length, position) =>
    writeSync(fd, buffer, offset, length, position),
  fsyncSync: (fd) => {
    fsyncSync(fd);
  },
  closeSync: (fd) => {
    closeSync(fd);
  },
  readFileSync: (p) => readFileSync(p),
  renameSync: (o, n) => {
    renameSync(o, n);
  },
  unlinkSync: (p) => {
    unlinkSync(p);
  },
  statSync: (p) => statSync(p),
  ftruncateSync: (fd, len) => {
    ftruncateSync(fd, len);
  },
};

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

/**
 * Write every byte of `buffer`, looping until the whole buffer is consumed. A
 * single writeSync call is not guaranteed to consume the entire buffer, so the
 * returned count is advanced explicitly.
 */
function writeFull(fs: DurableFs, fd: number, buffer: Uint8Array): void {
  let offset = 0;
  while (offset < buffer.byteLength) {
    const written = fs.writeSync(fd, buffer, offset, buffer.byteLength - offset, null);
    if (written <= 0) {
      throw new Error("durable write failed to make progress");
    }
    offset += written;
  }
}

/** fsync a directory so a newly created directory entry becomes durable. */
function fsyncDirectory(fs: DurableFs, dir: string): void {
  const fd = fs.openSync(dir, "r", DIR_MODE);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * fsync an existing regular file so its data and inode metadata are durable.
 * Opened read-only with FILE_MODE; fsync does not require write access. This is
 * the file half of the barrier the idempotent paths below re-run so a retry
 * after a partial failure cannot report durability it never established.
 */
function fsyncExistingFile(fs: DurableFs, path: string): void {
  const fd = fs.openSync(path, "r", FILE_MODE);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Create `path` (and any missing ancestors) and make the new directory entries
 * durable. Missing components are collected before creation, created with
 * 0o700, then fsynced from the deepest component upward followed by the
 * deepest pre-existing ancestor. If `path` already exists this is a no-op.
 */
export function ensureDirectoryDurable(path: string, fs: DurableFs = nodeFs): void {
  const target = resolve(path);
  const missing: string[] = [];
  let probe = target;
  while (!fs.existsSync(probe)) {
    missing.unshift(probe);
    const parent = dirname(probe);
    if (parent === probe) break; // reached the filesystem root
    probe = parent;
  }
  if (missing.length === 0) return; // nothing created, nothing to flush

  fs.mkdirSync(target, { recursive: true, mode: DIR_MODE });
  for (let i = missing.length - 1; i >= 0; i--) {
    fsyncDirectory(fs, missing[i]);
  }
  // Flush the pre-existing parent that now holds the shallowest new entry.
  // Skip when the walk terminated at the filesystem root, in which case probe
  // is itself one of the newly created components and was already flushed.
  if (!missing.includes(probe)) {
    fsyncDirectory(fs, probe);
  }
}

/**
 * Attach a rollback failure to the primary write/fsync error without masking
 * it. The original error is what the caller must observe to fail closed, but a
 * failed rollback (the file could not be restored to its pre-append length) is
 * critical diagnostic context, so it is surfaced in the message and kept as the
 * error `cause`.
 */
function annotateRollbackFailure(primary: unknown, rollbackErr: unknown): void {
  const rollbackMsg = rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr);
  if (primary instanceof Error) {
    primary.message = `${primary.message} (torn-append rollback also failed: ${rollbackMsg})`;
    (primary as Error & { cause?: unknown }).cause = rollbackErr;
  }
}

/**
 * Durably append one line to a JSONL-style log file. Sequence: create parent
 * directories, open append/create with 0o600, write the complete UTF-8 line
 * plus exactly one newline, fsync the file, close it, and fsync the parent
 * directory when the file was newly created.
 *
 * Torn-append safety: the pre-append file length is recorded first (inside the
 * caller's audit lock, so no other appender can interleave). If the write or
 * fsync fails after some bytes may have landed, the file is truncated back to
 * that length and flushed before the ORIGINAL error propagates, so a partial
 * line can never be left behind to corrupt every subsequent append. A crash
 * that prevents this handler from running is recovered explicitly by
 * `repairAuditLogTail` (`catp log repair`), never silently by the append path.
 */
export function durableAppendLine(path: string, line: string, fs: DurableFs = nodeFs): void {
  const dir = dirname(path);
  ensureDirectoryDurable(dir, fs);
  const existed = fs.existsSync(path);
  // Rollback boundary: for an existing file this is its current length; for a
  // brand-new file it is 0 (a failed create leaves an empty file, not a torn one).
  const originalSize = existed ? fs.statSync(path).size : 0;
  const fd = fs.openSync(path, "a", FILE_MODE);
  let closed = false;
  try {
    writeFull(fs, fd, Buffer.from(line + "\n", "utf8"));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    closed = true;
  } catch (err) {
    // Roll back the torn append, then close without letting a secondary close
    // error (POSIX can report a pending EIO on close after a failed fsync) mask
    // the original write/fsync failure the caller must observe to fail closed.
    if (!closed) {
      try {
        fs.ftruncateSync(fd, originalSize);
        fs.fsyncSync(fd);
      } catch (rollbackErr) {
        annotateRollbackFailure(err, rollbackErr);
      }
      try {
        fs.closeSync(fd);
      } catch {
        // preserve the original exception
      }
    }
    throw err;
  }
  if (!existed) {
    fsyncDirectory(fs, dir);
  }
}

let tempCounter = 0;

function uniqueTempPath(dir: string, base: string): string {
  tempCounter = (tempCounter + 1) % Number.MAX_SAFE_INTEGER;
  return join(dir, `.${base}.${process.pid}.${Date.now()}.${tempCounter}.tmp`);
}

/**
 * Durably create an empty file (and its parent directories) if it does not
 * already exist: open append/create with 0o600, fsync the new file, close it,
 * then fsync the parent directory. When the file already exists the barrier is
 * re-established (fsync the existing file + its parent directory) WITHOUT
 * writing any bytes, so a prior attempt that created the file and then failed
 * the parent-dir fsync cannot leave a non-durable entry behind on retry. This
 * is used to materialize the audit log so a lock manager that resolves the
 * target realpath never bypasses the new-file durability path.
 */
export function durableCreateEmptyFile(path: string, fs: DurableFs = nodeFs): void {
  const dir = dirname(path);
  ensureDirectoryDurable(dir, fs);
  if (fs.existsSync(path)) {
    // Idempotent path: re-run the barrier rather than returning blindly. A
    // previous call may have created the file and thrown at the dir fsync, so
    // success here must still imply the file's existence is durable.
    fsyncExistingFile(fs, path);
    fsyncDirectory(fs, dir);
    return;
  }
  const fd = fs.openSync(path, "a", FILE_MODE);
  let closed = false;
  try {
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    closed = true;
  } catch (err) {
    if (!closed) {
      try {
        fs.closeSync(fd);
      } catch {
        // preserve the original exception
      }
    }
    throw err;
  }
  fsyncDirectory(fs, dir);
}

/**
 * Durably write content-addressed `bytes` to `path` via a same-directory temp
 * file: create parents, write the temp with 0o600, fsync it, close, atomically
 * rename onto the target, then fsync the parent directory.
 *
 * If the target already exists its bytes are compared: identical bytes
 * re-establish the durability barrier (fsync the existing file, then its parent
 * directory) and succeed WITHOUT rewriting, so a retry after "rename succeeded,
 * parent-dir fsync failed" cannot skip the barrier; differing bytes are reported
 * as corruption. Descriptors are closed and the temp file removed on any
 * failure while preserving the original exception.
 */
export function durableWriteContentAddressed(
  path: string,
  bytes: Uint8Array,
  fs: DurableFs = nodeFs,
): void {
  const dir = dirname(path);
  ensureDirectoryDurable(dir, fs);

  if (fs.existsSync(path)) {
    const existing = fs.readFileSync(path);
    if (Buffer.compare(Buffer.from(bytes), existing) !== 0) {
      throw new Error(`content-addressed file already exists with different bytes: ${path}`);
    }
    // Identical bytes are NOT an automatic success. A prior attempt may have
    // renamed the temp file into place and then failed the parent-dir fsync, so
    // neither the file's data nor its directory entry can be assumed durable.
    // Re-run the full barrier and fail closed if either flush fails; only then
    // report idempotent success. This is the exact window that let a retry
    // append an audit entry whose action sidecar was never made durable.
    fsyncExistingFile(fs, path);
    fsyncDirectory(fs, dir);
    return;
  }

  const temp = uniqueTempPath(dir, basename(path));
  const fd = fs.openSync(temp, "w", FILE_MODE);
  let closed = false;
  let renamed = false;
  try {
    writeFull(fs, fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    closed = true;
    fs.renameSync(temp, path);
    renamed = true;
    fsyncDirectory(fs, dir);
  } catch (err) {
    if (!closed) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore close failure; preserve the original error
      }
    }
    if (!renamed) {
      try {
        fs.unlinkSync(temp);
      } catch {
        // best-effort temp cleanup; preserve the original error
      }
    }
    throw err;
  }
}

/**
 * Storage seam threaded through the audit logger and hook options. It exists
 * solely so tests can inject failures; CLI execution always uses
 * {@link nodeAuditStorage}.
 */
export interface AuditStorage {
  ensureDirectoryDurable(path: string): void;
  createEmptyFile(path: string): void;
  appendLine(path: string, line: string): void;
  writeContentAddressed(path: string, bytes: Uint8Array): void;
}

/** Production {@link AuditStorage} backed by the fsync durable primitives. */
export const nodeAuditStorage: AuditStorage = {
  ensureDirectoryDurable: (path) => ensureDirectoryDurable(path),
  createEmptyFile: (path) => durableCreateEmptyFile(path),
  appendLine: (path, line) => durableAppendLine(path, line),
  writeContentAddressed: (path, bytes) => durableWriteContentAddressed(path, bytes),
};
