// Source: paipai-Studio/BioSeqs src/abi.mbt
// Verdict: likely_false_positive (LLM confirmed)
// Numeric byte offset calculation, not string path concat

pub fn read_dir_entry(dir_offset : Int, i : Int) -> Int {
  let abi_dir_entry_size = 28
  let pos = dir_offset + i * abi_dir_entry_size
  pos
}
