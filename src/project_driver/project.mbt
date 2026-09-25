///|
pub(all) struct Verification {
  status : String
  detail : String
  toolchain : String
  target : String
  files : Array[String]
  unsupported : Array[String]
  snapshot : Map[String, String]
}

///|
fn failed(status : String, detail : String, target : String) -> Verification {
  {
    status,
    detail,
    target,
    toolchain: "",
    files: [],
    unsupported: [],
    snapshot: Map([]),
  }
}

///|
pub fn absolute(path : String) -> String {
  @path.Path(path).resolve().0.replace(old="\\", new="/")
}

///|
fn join(root : String, path : String) -> String {
  @path.Path(root).join(@path.Path(path)).resolve().0.replace(old="\\", new="/")
}

///|
// moon's normalized dry-run output uses Unix quoting, including on Windows.
// Parse only; never execute text emitted by the build planner.
pub fn plan_words(line : String) -> Array[String]? {
  let words : Array[String] = []
  let mut word = StringBuilder()
  let mut quote = ' '
  let mut escaped = false
  let mut present = false
  for ch in line {
    if escaped {
      if quote == '"' && ch != '"' && ch != '\\' && ch != '$' && ch != '`' {
        word.write_char('\\')
      }
      word.write_char(ch)
      escaped = false
      present = true
    } else if ch == '\\' && quote != '\'' {
      escaped = true
      present = true
    } else if quote != ' ' {
      if ch == quote {
        quote = ' '
      } else {
        word.write_char(ch)
      }
    } else if ch == '\'' || ch == '"' {
      quote = ch
      present = true
    } else if ch == ' ' || ch == '\t' || ch == '\r' {
      if present {
        words.push(word.to_string())
        word = StringBuilder()
        present = false
      }
    } else {
      word.write_char(ch)
      present = true
    }
  }
  if escaped || quote != ' ' {
    return None
  }
  if present {
    words.push(word.to_string())
  }
  Some(words)
}

///|
pub fn file_plan(
  output : String,
  root : String,
) -> (Array[String], Array[String])? {
  let files : Map[String, Bool] = Map([])
  let unsupported : Map[String, Bool] = Map([])
  let mut commands = 0
  for line in output.split("\n") {
    let words = match plan_words(line.to_owned()) {
      Some(words) => words
      None => return None
    }
    if words.length() < 2 {
      continue
    }
    let base = words[0]
      .replace(old="\\", new="/")
      .split("/")
      .to_array()
      .last()
      .unwrap()
      .to_owned()
    if (base != "moonc" && base != "moonc.exe") || words[1] != "check" {
      continue
    }
    commands += 1
    for operand in words[2:] {
      if !operand.has_suffix(".mbt") &&
        !operand.has_suffix(".mbt.md") &&
        !operand.has_suffix(".mbtx") {
        continue
      }
      let full = join(root, operand)
      if !full.has_prefix(root + "/") {
        continue
      }
      let relative = full[root.length() + 1:].to_owned()
      if relative.has_prefix(".mooncakes/") {
        continue
      }
      if operand.has_suffix(".mbt") {
        files[full] = true
      } else {
        unsupported[full] = true
      }
    }
  }
  if commands == 0 {
    return None
  }
  let selected = files.keys().to_array()
  let other = unsupported.keys().to_array()
  selected.sort()
  other.sort()
  Some((selected, other))
}

///|
fn snapshot_dir(
  root : String,
  result : Map[String, String],
  depth : Int,
  started : Int64,
  bytes : Ref[Int64],
) -> Unit raise {
  if @async.now() - started > 30000 {
    fail("snapshot_timeout")
  }
  if depth > 64 {
    fail("snapshot directory depth exceeded")
  }
  let entries = @fs.read_dir(root)
  for name in entries {
    if [".git", "_build", ".recovery"].contains(name) {
      continue
    }
    let path = join(root, name)
    let size = file_size(@utf8.encode(path) + b"\x00")
    if size < 0 {
      fail("snapshot cannot verify symlink or unreadable path: " + path)
    }
    if @fs.is_dir(path) {
      snapshot_dir(path, result, depth + 1, started, bytes)
    } else if name.has_suffix(".mbt") ||
      name.has_suffix(".mbt.md") ||
      name.has_suffix(".mbtx") ||
      [
        "moon.mod", "moon.mod.json", "moon.pkg", "moon.pkg.json", "moon.lock", "moon.work",
        "moon.work.json", ".moon-audit.json",
      ].contains(name) {
      if result.length() >= 100000 {
        fail("snapshot file limit exceeded")
      }
      if size > 16 * 1024 * 1024 || bytes.val + size > 256 * 1024 * 1024 {
        fail("snapshot_byte_limit")
      }
      bytes.val += size
      let data = @fs.read_file_to_bytes(path)
      result[path] = @crypto.bytes_to_hex_string(@crypto.sha256(data))
    }
  }
}

///|
pub fn snapshot(root : String) -> Map[String, String] raise {
  let result : Map[String, String] = Map([])
  snapshot_dir(root, result, 0, @async.now(), { val: 0, })
  result
}

///|
pub fn unchanged(before : Map[String, String], root : String) -> Bool {
  let after = snapshot(root) catch { _ => return false }
  if before.length() != after.length() {
    return false
  }
  before.iter().all(fn(pair) { after.get(pair.0) == Some(pair.1) })
}

///|
async fn read_bounded(reader : @process.ReadFromProcess) -> String {
  defer reader.close()
  let buffer = @buffer.Buffer()
  while reader.read_some(max_len=8192) is Some(chunk) {
    if buffer.length() + chunk.length() > 16 * 1024 * 1024 {
      fail("compiler_output_limit")
    }
    buffer.write_bytes(chunk)
  }
  @utf8.decode(buffer.to_bytes())
}

///|
async fn command(
  executable : String,
  args : Array[String],
  root : String,
  env : Map[String, String],
  timeout : Int,
) -> (Int, String, String) {
  if executable.contains("\u0000") ||
    args.any(fn(arg) { arg.contains("\u0000") }) {
    fail("NUL in compiler argument")
  }
  let self_exe = @utf8.decode(executable_bytes())
  if self_exe.is_empty() {
    fail("cannot locate native executable")
  }
  @async.with_timeout(timeout * 1000, () => {
    let (r_out, w_out) = @process.read_from_process()
    let (r_err, w_err) = @process.read_from_process()
    @async.with_task_group(group => {
      let launch = ["--internal-supervise", executable]
      for arg in args {
        launch.push(arg)
      }
      let child = @process.spawn(
        group,
        self_exe,
        launch,
        cwd=root,
        extra_env=env,
        stdout=w_out,
        stderr=w_err,
        cancel_handler=@process.CancellationHandler(pid => stop_tree(pid, 1)),
      )
      defer stop_tree(child.pid, 0)
      let stdout = group.spawn(() => read_bounded(r_out))
      let stderr = group.spawn(() => read_bounded(r_err))
      (child.wait(), stdout.wait(), stderr.wait())
    })
  })
}

///|
pub async fn verify(
  root : String,
  executable : String,
  toolchain_home : String?,
  target : String,
  timeout : Int,
) -> Verification {
  let env : Map[String, String] = Map([])
  match toolchain_home {
    Some(home) => {
      env["MOON_HOME"] = home
      env["PATH"] = join(home, "bin") +
        @path.delimiter.to_string() +
        @env.get_env_var("PATH").unwrap_or("")
    }
    None => ()
  }
  let initial = snapshot(root) catch {
    e => return failed("snapshot_unavailable", e.to_string(), target)
  }
  let mut version = command(
    executable,
    ["version", "--all"],
    root,
    env,
    timeout,
  ) catch {
    e => return failed("toolchain_unavailable", e.to_string(), target)
  }
  if version.0 != 0 {
    // Older moon --all also invokes optional Node-based moon-pilot. Its failure
    // must not make an otherwise usable compiler unavailable.
    let simple = command(executable, ["version"], root, env, timeout) catch {
      e => return failed("toolchain_unavailable", e.to_string(), target)
    }
    let compiler = match toolchain_home {
      Some(home) =>
        join(
          home,
          if @path.sep == '\\' {
            "bin/moonc.exe"
          } else {
            "bin/moonc"
          },
        )
      None =>
        if @path.Path(executable).is_absolute() {
          join(
            @path.Path(executable).dirname().0,
            if @path.sep == '\\' {
              "moonc.exe"
            } else {
              "moonc"
            },
          )
        } else {
          "moonc"
        }
    }
    let compiler_version = command(compiler, ["-v"], root, env, timeout) catch {
      _ => (1, "", "compiler identity unavailable")
    }
    if simple.0 == 0 && compiler_version.0 == 0 {
      version = (0, simple.1 + compiler_version.1 + compiler_version.2, "")
    }
  }
  if version.0 != 0 {
    return failed("toolchain_unavailable", version.2 + version.1, target)
  }
  let identity = version.1.trim().to_owned()
  let checked = command(
    executable,
    ["check", "--frozen", "--target", target],
    root,
    env,
    timeout,
  ) catch {
    e =>
      return {
        ..failed("compiler_execution_failed", e.to_string(), target),
        toolchain: identity,
      }
  }
  if checked.0 != 0 {
    return {
      ..failed("compiler_rejected", checked.2 + checked.1, target),
      toolchain: identity,
    }
  }
  let plan = command(
    executable,
    ["check", "--frozen", "--target", target, "--dry-run", "--verbose"],
    root,
    env,
    timeout,
  ) catch {
    e =>
      return {
        ..failed("compiler_plan_unavailable", e.to_string(), target),
        toolchain: identity,
      }
  }
  if plan.0 != 0 {
    return {
      ..failed("compiler_plan_unavailable", plan.2 + plan.1, target),
      toolchain: identity,
    }
  }
  let (files, unsupported) = match file_plan(plan.1, root) {
    Some(plan) => plan
    None =>
      return {
        ..failed(
          "compiler_plan_unavailable", "Unrecognized compiler file plan", target,
        ),
        toolchain: identity,
      }
  }
  let status = if !unchanged(initial, root) {
    "project_changed"
  } else if files.is_empty() || !unsupported.is_empty() {
    "scope_incomplete"
  } else {
    "compiler_verified"
  }
  {
    status,
    detail: "",
    toolchain: identity,
    target,
    files,
    unsupported,
    snapshot: initial,
  }
}

///|
pub fn Verification::to_json(self : Verification) -> Json {
  let hashes : Map[String, Json] = Map([])
  for path, hash in self.snapshot {
    hashes[path] = Json::string(hash)
  }
  {
    "status": Json::string(self.status),
    "detail": Json::string(self.detail),
    "toolchain": Json::string(self.toolchain),
    "target": Json::string(self.target),
    "compiler_files": Json::array(self.files.map(Json::string)),
    "unsupported_files": Json::array(self.unsupported.map(Json::string)),
    "snapshot_sha256": Json::object(hashes),
  }
}

///|
extern "C" fn isolate() -> Int = "audit_isolate"

///|
extern "C" fn stop_tree(pid : Int, direct : Int) -> Unit = "audit_stop_tree"

///|
extern "C" fn executable_bytes() -> Bytes = "audit_executable"

///|
// Private self-invocation: isolate before any compiler descendant is created.
pub async fn supervise(args : Array[String]) -> Int {
  if args.length() < 3 || isolate() == 0 {
    return 125
  }
  @process.run(args[2], args[3:].to_owned())
}

///|
#borrow(path)
extern "C" fn file_size(path : Bytes) -> Int64 = "audit_file_size"

///|
pub async fn definition(
  root : String,
  executable : String,
  home : String?,
  file : String,
  line : Int,
  column : Int,
  bootstrap : Bool,
) -> Json {
  let env : Map[String, String] = Map([])
  if home is Some(home) {
    env["MOON_HOME"] = home
    env["PATH"] = join(home, "bin") +
      @path.delimiter.to_string() +
      @env.get_env_var("PATH").unwrap_or("")
  }
  let relative = @path.Path(file).relative(base=@path.Path(root)).0
  let args = [
    "ide",
    "peek-def",
    "--json",
    "--target",
    "native",
    "--loc",
    relative + ":" + line.to_string() + ":" + column.to_string(),
  ]
  if !bootstrap {
    args.push("--no-check")
  }
  let result = command(executable, args, root, env, 30)
  if result.0 != 0 {
    fail("binding_unavailable: " + result.2)
  }
  @json.parse(result.1)
}

///|
extern "C" fn set_memory_limit(mebibytes : Int) -> Int = "audit_limit_memory"

///|
pub fn limit_worker_memory(mebibytes : Int) -> Bool {
  set_memory_limit(mebibytes) == 1
}

///|
pub async fn semantic_worker(
  root : String,
  executable : String,
  home : String?,
  timeout : Int,
) -> Json {
  let self_exe = @utf8.decode(executable_bytes())
  let result = command(
    self_exe,
    ["--internal-semantic", root, executable, home.unwrap_or("")],
    root,
    Map([]),
    timeout,
  )
  if result.0 != 0 && result.0 != 2 {
    fail("semantic_worker_failed: " + result.0.to_string())
  }
  @json.parse(result.1)
}
