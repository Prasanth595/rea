/** Source-owned Cortex-M0 instructions; no third-party firmware or target execution.
 * Image offsets:
 *   00 initial stack pointer, 04 odd reset vector, 08..3f reserved vectors
 *   40 push {r4,lr}; movs r0,#7; bl add_three; cmp r0,#10; bne mismatch
 *   4c ldr r1,literal; ldr r0,[r1]; pop {r4,pc}
 *   52 mismatch: movs r0,#0; pop {r4,pc}
 *   56 add_three: adds r0,#3; bx lr
 *   5a mov r8,r8 (alignment padding), 5c absolute pointer, 60 payload 42
 * The instruction bytes were independently assembled with Clang's cortex-m0
 * target. Only the vector and absolute data pointer vary with the load base.
 */
export const cortexM0Fixture = (base) => {
  const bytes = Buffer.alloc(100);
  bytes.writeUInt32LE(0x20001000, 0);
  bytes.writeUInt32LE(base + 0x41, 4);
  Buffer.from(
    "10b5072000f007f80a2802d10349086810bd002010bd03307047c046",
    "hex",
  ).copy(bytes, 0x40);
  bytes.writeUInt32LE(base + 0x60, 0x5c);
  bytes.writeUInt32LE(42, 0x60);
  return bytes;
};
