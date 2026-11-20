// MachGraph M2 assembler vs clang test cases (Acceptance Table Row 13)
//
// Sources and generation rules:
// 1. Lines from flagship-acceptance harness/machgraph/{a.s, b.s, c.s, c2.s}
//    deduplicated in that exact file and line order (38 statements, copied verbatim).
// 2. One representative statement per reference encoding table added in M2 Stages 7-10
//    (16 tables under Fixtures/a64/*.tsv): the first row in each table that v1.3.0 (2ee33ed)
//    printed as .inst and 446900a decodes, using the verbatim LLVM reference column text.
//    Additional tables merged from M2 Lines A and C are appended by the same rule.
// 3. No semicolons are permitted in this file (Darwin clang treats them as comments,
//    whereas machgraph asm treats them as statement separators).

// --- Part 1: harness/machgraph/{a.s, b.s, c.s, c2.s} (38 deduplicated lines) ---
mov x0, #42
ret
stp x29, x30, [sp, #-16]!
ldp x29, x30, [sp], #16
stp x20, x19, [sp, #16]
adrp x8, .+4096
bl .+232
b.eq .+-12
cbz x0, .+0
add x0, x1, x2, lsl #3
ldr x0, .+-24
pacibsp
retab
sub sp, sp, #32
cmp w8, #1
ldr x1, [x2, #8]
str w3, [x4, x5, lsl #2]
csel x0, x1, x2, ne
movk x0, #0x1234, lsl #16
blr x8
tbz w1, #3, .+-64
fadd d0, d1, d2
ldp q0, q1, [sp]
umulh x0, x1, x2
madd x0, x1, x2, x3
svc #0x80
mrs x0, tpidr_el0
ldaxr x0, [x1]
cas x0, x1, [x2]
fmov d0, #1.0
ld1 {v0.4s}, [x0]
add v0.4s, v1.4s, v2.4s
sxtw x0, w1
ubfx x0, x1, #4, #8
ldrsw x0, [x1, #4]
ccmp w0, #1, #0, eq
csinc w0, wzr, wzr, ne
ret x1

// --- Part 2: M2 Stages 7-10 newly-added reference tables (16 tables, 1 row each) ---
// Fixtures/a64/advsimd_vec_three_same.tsv @ 0x0e230441
shadd v1.8b, v2.8b, v3.8b
// Fixtures/a64/advsimd_scalar_three_same.tsv @ 0x5e230c41
sqadd b1, b2, b3
// Fixtures/a64/advsimd_dot_product.tsv @ 0x0e839441
sdot v1.2s, v2.8b, v3.8b
// Fixtures/a64/advsimd_scalar_two_reg_misc.tsv @ 0x5e203841
suqadd b1, b2
// Fixtures/a64/advsimd_vec_two_reg_misc.tsv @ 0x0e200841
rev64 v1.8b, v2.8b
// Fixtures/a64/advsimd_vec_shift_imm_q0_u0.tsv @ 0x0f080441
sshr v1.8b, v2.8b, #0x8
// Fixtures/a64/advsimd_vec_shift_imm_q0_u1.tsv @ 0x2f080441
ushr v1.8b, v2.8b, #0x8
// Fixtures/a64/advsimd_vec_shift_imm_q1_u0.tsv @ 0x4f080441
sshr v1.16b, v2.16b, #0x8
// Fixtures/a64/advsimd_vec_shift_imm_q1_u1.tsv @ 0x6f080441
ushr v1.16b, v2.16b, #0x8
// Fixtures/a64/advsimd_scalar_shift_imm_u0.tsv @ 0x5f087441
sqshl b1, b2, #0x0
// Fixtures/a64/advsimd_scalar_shift_imm_u1.tsv @ 0x7f086441
sqshlu b1, b2, #0x0
// Fixtures/a64/scalar_fp_fixed_point.tsv @ 0x1e028041
scvtf s1, w2, #0x20
// Fixtures/a64/pac_data_ptr.tsv @ 0xdac12be1
pacdza x1
// Fixtures/a64/rcpc_ldapr.tsv @ 0x38bfc041
ldaprb w1, [x2]
// Fixtures/a64/scalar_fp_int_conv.tsv @ 0x1e200041
fcvtns w1, s2
// Fixtures/a64/scalar_fp_one_source.tsv @ 0x1e264041
frinta s1, s2

// --- Part 3: Post-446900a merged reference tables (17 rows added, load_store_exclusive_casp 0x080420c2 omitted per clang word-equality rule) ---
// Fixtures/a64/advsimd_across_lanes.tsv @ 0x0e303841
saddlv h1, v2.8b
// Fixtures/a64/advsimd_ext.tsv @ 0x2e030041
ext v1.8b, v2.8b, v3.8b, #0x0
// Fixtures/a64/advsimd_ldst_multi.tsv @ 0x0c000041
st4 { v1.8b, v2.8b, v3.8b, v4.8b }, [x2]
// Fixtures/a64/advsimd_ldst_single.tsv @ 0x0d000041
st1 { v1.b }[0], [x2]
// Fixtures/a64/advsimd_modified_imm.tsv @ 0x0f001401
orr v1.2s, #0x0
// Fixtures/a64/advsimd_permute.tsv @ 0x0e031841
uzp1 v1.8b, v2.8b, v3.8b
// Fixtures/a64/advsimd_scalar_by_element.tsv @ 0x5f031041
fmla h1, h2, v3.h[0]
// Fixtures/a64/advsimd_scalar_copy.tsv @ 0x5e010441
mov b1, v2.b[0]
// Fixtures/a64/advsimd_scalar_pairwise.tsv @ 0x5e30c841
fmaxnmp h1, v2.2h
// Fixtures/a64/advsimd_table_lookup.tsv @ 0x0e030041
tbl v1.8b, { v2.16b }, v3.8b
// Fixtures/a64/advsimd_three_different.tsv @ 0x0e230041
saddl v1.8h, v2.8b, v3.8b
// Fixtures/a64/advsimd_vector_by_element.tsv @ 0x0f031041
fmla v1.4h, v2.4h, v3.h[0]
// Fixtures/a64/barriers.tsv @ 0xd503301f
msr S0_3_C3_C0_0, xzr
// Fixtures/a64/crypto_aes.tsv @ 0x4e284841
aese v1.16b, v2.16b
// Fixtures/a64/crypto_sha.tsv @ 0x5e030041
sha1c q1, s2, v3.4s
// Fixtures/a64/crypto_sha3.tsv @ 0xce031041
eor3 v1.16b, v2.16b, v3.16b, v4.16b
// Fixtures/a64/scalar_fp_three_source.tsv @ 0x1f231041
fnmadd s1, s2, s3, s4
