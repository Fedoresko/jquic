# Agent Guidelines

**Junie** Hi Junie! Never modify implementation code until explicitlety asked! If some test fail you must only suggest a fix by default, note make it.   
**Context analysis.** Do not spend tokens to analyze the whole project context of not asked explicitly, take what is sufficient only.

## Buffer Handling: Zero-Copy Policy

**Always use a zero-copy approach when building or processing byte buffers.**

### Rules

- **Single allocation.** Allocate one `ByteBuffer` sized to the maximum expected output. Never allocate intermediate/temporary buffers just to copy their contents into another buffer.
- **Back-fill lengths in place.** When a length field must precede data whose size is not yet known, record the field's position, write a placeholder, fill in the data, then seek back and patch the length — all within the same buffer.
- **No intermediate copies.** Do not create helper buffers (e.g. `tpBuf`, `valBuf`, `body`) whose sole purpose is to be `put()` into a parent buffer. Write directly to the final buffer instead.
- **Prefer `ByteBuffer` slice/duplicate over copying.** When you need a read-only view of a sub-region, use `buffer.slice()` or `buffer.duplicate()` with adjusted `position`/`limit`, not `System.arraycopy` or a new allocation.
- **Flip once, at the end.** Call `flip()` exactly once on the final buffer before returning or passing it on. Avoid repeated flip/rewind cycles.
- **Use `allocateDirect` for I/O paths.** Direct buffers avoid an extra kernel-copy when data is passed to native I/O calls (e.g. `DatagramChannel.send`).

### Example pattern

```java
ByteBuffer buf = ByteBuffer.allocate(MAX_SIZE);

buf.put((byte) TYPE);

int lenPos = buf.position();          // remember where the length field goes
buf.putShort((short) 0);              // placeholder

int dataStart = buf.position();
// ... write data directly into buf ...
int dataLen = buf.position() - dataStart;

buf.putShort(lenPos, (short) dataLen); // back-fill length in place

buf.flip();
return buf;
```

### What to avoid

```java
// ❌ Anti-pattern: intermediate buffer copied into the parent
ByteBuffer tmp = ByteBuffer.allocate(64);
writeData(tmp);
tmp.flip();
parent.put(tmp); // unnecessary copy
```</llm-patch>
