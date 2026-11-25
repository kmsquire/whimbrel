//! The pinned lists: which repo, which commit, which files, and each file's checksum. Files are
//! fetched from GitHub at the pinned commit and refused if their checksum differs.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
pub struct Sources {
    pub source: Vec<Source>,
}

#[derive(Deserialize, Clone)]
pub struct Source {
    /// What the built-ins call the list: a shape's `source`.
    pub name: String,
    /// `owner/name` on GitHub.
    pub repo: String,
    pub commit: String,
    /// The tag at that commit, if it's a release, for the prose in THIRD-PARTY.md.
    pub tag: Option<String>,
    pub format: Format,
    /// For `toml`, the one file read; for `go`, the directory whose Go files are read.
    pub read: String,
    pub files: Vec<File>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// A gitleaks-style config: every `[[rules]]` entry with a `regex`.
    Toml,
    /// Go source: every `regexp.MustCompile` whose argument is one raw string literal.
    Go,
}

#[derive(Deserialize, Clone)]
pub struct File {
    pub path: String,
    pub sha256: String,
}

pub fn load(path: &Path) -> Result<Sources, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// How long one request may take, and how many times one is tried.
const TIMEOUT: Duration = Duration::from_secs(60);
const TRIES: u32 = 3;

fn get(url: &str) -> Result<Vec<u8>, String> {
    static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .build()
            .into()
    });
    let once = || -> Result<Vec<u8>, ureq::Error> {
        AGENT
            .get(url)
            .call()?
            .body_mut()
            .with_config()
            .limit(64 << 20)
            .read_to_vec()
    };
    let mut tried = 1;
    loop {
        match once() {
            Ok(bytes) => return Ok(bytes),
            // A refusal that won't change on a retry: a missing file, say.
            Err(ureq::Error::StatusCode(code)) if (400..500).contains(&code) && code != 429 => {
                return Err(format!("couldn't fetch {url}: HTTP {code}"));
            }
            Err(e) if tried >= TRIES => {
                return Err(format!(
                    "couldn't fetch {url} in {TRIES} tries: {e}\nThe tool reads the pinned lists \
                     from GitHub, so it needs the network."
                ));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_secs(2u64.pow(tried)));
                tried += 1;
            }
        }
    }
}

/// The file's bytes at the source's commit, from the cache under `cache` if it holds them, and
/// only if their checksum is the pinned one.
pub fn fetch(source: &Source, file: &File, cache: &Path) -> Result<Vec<u8>, String> {
    let cached: PathBuf = cache.join(&file.sha256);
    if let Ok(bytes) = fs::read(&cached)
        && sha256(&bytes) == file.sha256
    {
        return Ok(bytes);
    }
    let url = raw_url(source, &file.path);
    let bytes = get(&url)?;
    let got = sha256(&bytes);
    if got != file.sha256 {
        return Err(format!(
            "{url} has checksum {got}, but sources.toml pins {}",
            file.sha256
        ));
    }
    fs::create_dir_all(cache).map_err(|e| format!("{}: {e}", cache.display()))?;
    fs::write(&cached, &bytes).map_err(|e| format!("{}: {e}", cached.display()))?;
    Ok(bytes)
}

fn raw_url(source: &Source, path: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/{}/{}/{path}",
        source.repo, source.commit
    )
}

/// Moves `source` to `commit`: lists the files it reads there and pins each one's checksum.
pub fn bump(source: &mut Source, commit: &str, tag: Option<String>) -> Result<(), String> {
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{commit:?} isn't a full 40-character commit"));
    }
    source.commit = commit.to_ascii_lowercase();
    source.tag = tag;
    let paths = match source.format {
        Format::Toml => vec![source.read.clone()],
        Format::Go => {
            let url = format!(
                "https://api.github.com/repos/{}/git/trees/{}?recursive=1",
                source.repo, source.commit
            );
            let tree: serde_json::Value =
                serde_json::from_slice(&get(&url)?).map_err(|e| format!("{url}: {e}"))?;
            if tree["truncated"].as_bool() != Some(false) {
                return Err(format!("{url} didn't list the whole tree"));
            }
            let dir = format!("{}/", source.read.trim_end_matches('/'));
            let mut paths: Vec<String> = tree["tree"]
                .as_array()
                .ok_or_else(|| format!("{url} has no tree"))?
                .iter()
                .filter(|e| e["type"] == "blob")
                .filter_map(|e| e["path"].as_str())
                .filter(|p| p.starts_with(&dir) && p.ends_with(".go") && !p.ends_with("_test.go"))
                .map(str::to_string)
                .collect();
            paths.sort();
            paths
        }
    };
    if paths.is_empty() {
        return Err(format!("{} reads no files at {commit}", source.name));
    }
    source.files = paths
        .into_iter()
        .map(|path| {
            let bytes = get(&raw_url(source, &path))?;
            Ok(File {
                sha256: sha256(&bytes),
                path,
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(())
}

/// `sources.toml` as the tool writes it.
pub fn render(sources: &Sources) -> String {
    let mut out = String::from(
        "# The lists the built-in secret patterns are taken from, in the order they're taken. Every file\n\
         # read is pinned by checksum. Don't edit the commits or the files by hand: run the tool's `bump`.\n",
    );
    for s in &sources.source {
        out += "\n[[source]]\n";
        out += &format!("name = {}\n", crate::toml_str(&s.name));
        out += &format!("repo = {}\n", crate::toml_str(&s.repo));
        out += &format!("commit = {}\n", crate::toml_str(&s.commit));
        if let Some(tag) = &s.tag {
            out += &format!("tag = {}\n", crate::toml_str(tag));
        }
        let format = match s.format {
            Format::Toml => "toml",
            Format::Go => "go",
        };
        out += &format!("format = \"{format}\"\n");
        out += &format!("read = {}\n", crate::toml_str(&s.read));
        out += "files = [\n";
        for f in &s.files {
            out += &format!(
                "  {{ path = {}, sha256 = \"{}\" }},\n",
                crate::toml_str(&f.path),
                f.sha256
            );
        }
        out += "]\n";
    }
    out
}
