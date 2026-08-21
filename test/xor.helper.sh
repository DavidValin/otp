#!/bin/sh

# Shared test helper: XOR two files byte by byte, independently of the
# binary under test. The suites use this to compute the expected result
# of an encrypt/decrypt from a known key slice, so the expectation is
# produced by different code than the code being verified.
#
# xor_with_key <keyfile> <datafile> <outfile>
#   XORs every byte of <datafile> with the byte at the same position of
#   <keyfile> (which must be at least as long) and writes the result to
#   <outfile>. Bytes are round-tripped as decimal via od(1) and combined
#   in awk (bit by bit - POSIX awk has no xor()), then emitted as octal
#   escapes for printf, which handles NUL and every other byte value.
xor_with_key() {
  XW_KEY=$1
  XW_DATA=$2
  XW_OUT=$3
  XW_LEN=$(wc -c < "$XW_DATA" | tr -d ' ')
  XW_ESC=$(
    {
      od -An -v -tu1 "$XW_DATA"
      echo "XORSEP"
      dd if="$XW_KEY" bs=1 count="$XW_LEN" 2>/dev/null | od -An -v -tu1
    } | awk '
      /^XORSEP$/ { insep = 1; next }
      {
        for (i = 1; i <= NF; i++) {
          if (!insep) d[nd++] = $i; else k[nk++] = $i
        }
      }
      END {
        for (j = 0; j < nd; j++) {
          x = 0
          for (b = 1; b < 256; b *= 2)
            if (int(d[j] / b) % 2 != int(k[j] / b) % 2) x += b
          printf "\\%03o", x
        }
      }'
  )
  # The escape string contains only backslash-octal sequences, so it is
  # safe to hand to printf as a format string.
  printf "$XW_ESC" > "$XW_OUT"
}

# ---------------------------------------------------------------------------
# Per-message metadata helpers (v1.6.0 wire format)
#
# Every ciphertext opens with an encrypted binary metadata block:
#   \001 <source_id: 16 bytes>  \002 <len> <seq BE>  \003 <len> <off BE>
# The key range a message consumes is contiguous: 16 source_id bytes
# first (embedded in the metadata, never used as pad), then the XOR pad
# for metadata+plaintext. These helpers rebuild that format from scratch
# - independently of the binary under test - so suites can compute
# expected ciphertexts and craft deliberately invalid ones.
# ---------------------------------------------------------------------------

# meta_uint_esc <value> -> minimal big-endian bytes as \NNN octal escapes
meta_uint_esc() {
  awk -v v="$1" 'BEGIN{
    n=0
    if (v == 0) { b[n++] = 0 } else { while (v > 0) { b[n++] = v % 256; v = int(v / 256) } }
    for (i = n - 1; i >= 0; i--) printf "\\%03o", b[i]
  }'
}

# meta_uint_len <value> -> how many bytes meta_uint_esc uses
meta_uint_len() {
  awk -v v="$1" 'BEGIN{n=0; if (v==0) n=1; else while (v>0) {n++; v=int(v/256)}; print n}'
}

# meta_consumed_len <plaintext_len> <seq> <offset>
#   Total key bytes one message consumes: 16 (source_id) + metadata pad
#   (21 + len(seq) + len(off)) + plaintext pad.
meta_consumed_len() {
  echo $(( $1 + 37 + $(meta_uint_len "$2") + $(meta_uint_len "$3") ))
}

# make_meta <keyfile> <skip> <seq> <offset> <outfile>
#   The metadata PLAINTEXT block for a message whose key range starts at
#   byte <skip> of <keyfile> (source_id = the 16 key bytes there).
make_meta() {
  MM_KEY=$1; MM_SKIP=$2; MM_SEQ=$3; MM_OFF=$4; MM_OUT=$5
  {
    printf '\001'
    dd if="$MM_KEY" bs=1 skip="$MM_SKIP" count=16 2>/dev/null
    printf '\002'
    printf "$(meta_uint_esc "$(meta_uint_len "$MM_SEQ")")"
    printf "$(meta_uint_esc "$MM_SEQ")"
    printf '\003'
    printf "$(meta_uint_esc "$(meta_uint_len "$MM_OFF")")"
    printf "$(meta_uint_esc "$MM_OFF")"
  } > "$MM_OUT"
}

# make_cipher <keyfile> <skip> <plainfile> <seq> <offset> <outfile>
#   Full expected ciphertext: metadata (source_id from <keyfile> at
#   <skip>, declaring <seq>/<offset>) + plaintext, XORed with the key
#   run starting at <skip>+16. <skip> is where the message's key range
#   begins in <keyfile>; for an untruncated original key copy that is
#   the same number as the absolute <offset> the metadata declares -
#   craft mismatches by passing them differently.
make_cipher() {
  MK_KEY=$1; MK_SKIP=$2; MK_PLAIN=$3; MK_SEQ=$4; MK_OFF=$5; MK_OUT=$6
  make_meta "$MK_KEY" "$MK_SKIP" "$MK_SEQ" "$MK_OFF" mk_meta.tmp
  cat mk_meta.tmp "$MK_PLAIN" > mk_full.tmp
  MK_N=$(wc -c < mk_full.tmp | tr -d ' ')
  dd if="$MK_KEY" of=mk_slice.tmp bs=1 skip=$((MK_SKIP + 16)) count="$MK_N" 2>/dev/null
  xor_with_key mk_slice.tmp mk_full.tmp "$MK_OUT"
  rm -f mk_meta.tmp mk_full.tmp mk_slice.tmp
}

# make_cipher_srcfile <keyfile> <skip> <srcfile> <plainfile> <seq> <offset> <outfile>
#   Same as make_cipher but the 16-byte source_id comes from <srcfile>
#   instead of the key - for crafting messages with a wrong source_id.
make_cipher_srcfile() {
  MS_KEY=$1; MS_SKIP=$2; MS_SRC=$3; MS_PLAIN=$4; MS_SEQ=$5; MS_OFF=$6; MS_OUT=$7
  {
    printf '\001'
    dd if="$MS_SRC" bs=1 count=16 2>/dev/null
    printf '\002'
    printf "$(meta_uint_esc "$(meta_uint_len "$MS_SEQ")")"
    printf "$(meta_uint_esc "$MS_SEQ")"
    printf '\003'
    printf "$(meta_uint_esc "$(meta_uint_len "$MS_OFF")")"
    printf "$(meta_uint_esc "$MS_OFF")"
  } > ms_meta.tmp
  cat ms_meta.tmp "$MS_PLAIN" > ms_full.tmp
  MS_N=$(wc -c < ms_full.tmp | tr -d ' ')
  dd if="$MS_KEY" of=ms_slice.tmp bs=1 skip=$((MS_SKIP + 16)) count="$MS_N" 2>/dev/null
  xor_with_key ms_slice.tmp ms_full.tmp "$MS_OUT"
  rm -f ms_meta.tmp ms_full.tmp ms_slice.tmp
}

# make_cipher_from_meta <keyfile> <skip> <metafile> <plainfile> <outfile>
#   Like make_cipher, but the metadata PLAINTEXT block is supplied
#   prebuilt in <metafile> - for crafting nonstandard encodings (varint
#   length fields, non-minimal or arbitrarily wide seq/offset values).
make_cipher_from_meta() {
  MF_KEY=$1; MF_SKIP=$2; MF_META=$3; MF_PLAIN=$4; MF_OUT=$5
  cat "$MF_META" "$MF_PLAIN" > mf_full.tmp
  MF_N=$(wc -c < mf_full.tmp | tr -d ' ')
  dd if="$MF_KEY" of=mf_slice.tmp bs=1 skip=$((MF_SKIP + 16)) count="$MF_N" 2>/dev/null
  xor_with_key mf_slice.tmp mf_full.tmp "$MF_OUT"
  rm -f mf_full.tmp mf_slice.tmp
}
