// Reject special files before synchronous reads; applies to source and metadata.

///|
pub fn read_regular_text(path : String) -> String raise {
  if !(@fs.is_file(path) catch { _ => false }) {
    fail("Not a readable regular file: " + path)
  }
  @fs.read_file_to_string(path)
}
