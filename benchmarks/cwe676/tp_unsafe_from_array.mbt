// Source: paipai-Studio/BioSeqs src/bam.mbt
// Verdict: needs_review (audit_hint — unsafe conversion from raw buffer)
// Buffer built from decoded BAM data; bounds not checked before unsafe call

fn unsafe_from_uint16_fixedarray(buf : FixedArray[UInt16]) -> String {
  ""
}

pub fn decode_bam_seq(encoded : String, length : Int) -> String {
  let buf : FixedArray[UInt16] = FixedArray::make(length, 0)
  let mut i = 0
  while i < length {
    buf[i] = encoded[i].to_int().to_uint16()
    i = i + 1
  }
  unsafe_from_uint16_fixedarray(buf)
}
