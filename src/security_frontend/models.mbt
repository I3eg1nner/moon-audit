///|
fn model_declarations() -> Array[(String, String, String, String)] {
  [
    (
      "intrinsics.mbt", "1887:33-1887:36", "54b050d9ae60b256174d74521e8fc7835550dedb4bf94cde5fcfbccbcbe2ceb0",
      "string_concat",
    ),
    (
      "html.mbt", "1032:8-1032:14", "0af18ff6ff3e4c14eab41f85127389ef598086020035dfe59e61713b4d0950dd",
      "markdown",
    ),
    (
      "index.mbt", "152:16-152:19", "9109bffdc75e47e5793c9fcd6c89cb19a71a9ac25d64fafa1c7ac7c7853ad973",
      "route",
    ),
    (
      "event.mbt", "3:3-3:6", "1146bde3891781984d0c98e84386a4b423d753d2cadc5f9095e51e2c258a76db",
      "request",
    ),
    (
      "request.mbt", "33:21-33:26", "b8a10625f022328175f087b4ebdd8eb4e838763bf2d6c45ee414304803f3ff43",
      "query",
    ),
    (
      "linked_hash_map.mbt", "269:31-269:34", "fe413a7ffa2e4148abf2f37b01decef05e544e998b3cd730a73817830a63bfd6",
      "lookup",
    ),
    (
      "option.mbt", "48:19-48:28", "059fcefd01f0393fc0ded6456e28d3dc0699dd6c32fdd0ac80aadbb35473184a",
      "default",
    ),
    (
      "responder.mbt", "92:8-92:12", "4b273a040c4ce219b9c2f0a7c810be90c873d3aad3062a9076e0d3e9f5e2e6b9",
      "html",
    ),
    (
      "utils.mbt", "128:8-128:19", "66c99f7c77a01765262e89a96148624440048fd856e79486cf4ddfb200a3e0c3",
      "escape",
    ),
    (
      "responder.mbt", "97:8-97:12", "4b273a040c4ce219b9c2f0a7c810be90c873d3aad3062a9076e0d3e9f5e2e6b9",
      "text",
    ),
  ]
}

///|
fn collect_model_files(
  root : String,
  relative : String,
  files : Array[String],
  depth : Int,
) -> Unit raise {
  if depth > 64 || files.length() > 10000 {
    fail("model_snapshot_budget")
  }
  let directory = @path.Path(root).join(@path.Path(relative)).0
  for name in @fs.read_dir(directory) {
    if [
        ".git", "_build", "target", ".moon-audit-cache", "__pycache__", ".mooncakes",
      ].contains(name) {
      continue
    }
    let rel = if relative == "" { name } else { relative + "/" + name }
    let path = @path.Path(root).join(@path.Path(rel)).0
    if @fs.is_dir(path) {
      collect_model_files(root, rel, files, depth + 1)
    } else if @fs.is_file(path) {
      files.push(rel + " " + hash(path) + "\n")
    } else {
      fail("nonregular_model_file")
    }
  }
}

///|
fn tree_hash(root : String) -> String raise {
  let files : Array[String] = []
  collect_model_files(root, "", files, 0)
  files.sort_by(String::lexical_compare)
  @crypto.bytes_to_hex_string(@crypto.sha256(@utf8.encode(files.join(""))))
}

///|
fn verify_mocket_package(root : String) -> Bool {
  if (tree_hash(root) catch { _ => "" }) !=
    "3c878bf5fe70379151d6fd20879d81c905cfec8bdbcef1f616a2079a54d5f847" {
    return false
  }
  let modules = if (@fs.is_dir(
      @path.Path(root).join(@path.Path(".mooncakes")).0,
    ) catch {
      _ => false
    }) {
    @path.Path(root).join(@path.Path(".mooncakes")).0
  } else {
    @path.Path(root).dirname().dirname().0
  }
  if (tree_hash(@path.Path(modules).join(@path.Path("moonbitlang/async")).0) catch {
      _ => ""
    }) !=
    "a24cfd73b4efdbcedc704dabaf60d3bf7dbc3e664de9fbd8be753a15aa2c9682" {
    return false
  }
  if (tree_hash(@path.Path(modules).join(@path.Path("moonbitlang/x")).0) catch {
      _ => ""
    }) !=
    "043bb41508e0633142118f59f18e1abe27e7636f7c1224a8e9a30c23581f78b9" {
    return false
  }
  if (tree_hash(@path.Path(modules).join(@path.Path("oboard/mimetype")).0) catch {
      _ => ""
    }) !=
    "882010328b97ee3d6c2ac37a8e8c5de0a469dcadc7338ba99b0a362399ca8367" {
    return false
  }
  true
}

///|
fn verify_cmark_package(package_dir : String) -> Bool {
  let root = @path.Path(package_dir).dirname().dirname().0
  if (tree_hash(root) catch { _ => "" }) !=
    "23482be6d6ef40016fd56526c198717c098893c7ccd20b92f9f920135a7e9283" {
    return false
  }
  let modules = @path.Path(root).dirname().dirname().0
  if (tree_hash(
      @path.Path(modules).join(@path.Path("moonbit-community/casefold")).0,
    ) catch {
      _ => ""
    }) !=
    "dbf16e3266e0d1dcd502c3a0aa4958555c475f135453483c39268d2fbec677b6" {
    return false
  }
  if (tree_hash(
      @path.Path(modules).join(@path.Path("moonbit-community/charclass")).0,
    ) catch {
      _ => ""
    }) !=
    "e4e76b35fc20f922cc9a78272ea9c6cd1acdfe599ed7e7434a983ba6686f7e9d" {
    return false
  }
  if (tree_hash(@path.Path(modules).join(@path.Path("moonbit-community/ucd")).0) catch {
      _ => ""
    }) !=
    "b969ec765cfdf20c5c151dc4c3890bf2fb1f54699ed027cb820340f49d8ef3b8" {
    return false
  }
  true
}

///|
fn model_manifest() -> Json {
  model_declarations()
  .map(fn(item) {
    {
      "declaration_file": Json::string(item.0),
      "range": Json::string(item.1),
      "sha256": Json::string(item.2),
      "operation": Json::string(item.3),
    }
  })
  .to_json()
}
