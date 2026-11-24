# Third-party material

The built-in secret patterns in `src/secret_patterns.rs` are every rule of three published lists
that passes one test, the same for each list: the token starts the match with no keyword before
it, every way it matches starts with the same 3 or more fixed characters, it can't match fewer than
16 characters, it's a shape rather than one fixed string, it compiles in Rust's regex, and no rule taken from an earlier list already
matches an example of it. `src/secret_patterns.rs` states the test in full. Each pattern names
its source and rule, and says how it differs where it does. Only patterns are taken; no other
code is.

## gitleaks

The rules that pass the test from gitleaks' default configuration, `config/gitleaks.toml`, at
v8.30.1 (commit
`83d9cd684c87d95d656c1458ef04895a7f1cbd8e`):
<https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml>. Under the MIT license:

```text
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## betterleaks

The rules that pass the test from `config/betterleaks.toml`, taken after gitleaks', at commit
`c668bd014b9c586e94963538dd553e56f52decdb`:
<https://github.com/betterleaks/betterleaks/blob/c668bd014b9c586e94963538dd553e56f52decdb/config/betterleaks.toml>.
Under the MIT license:

```text
MIT License

Copyright (c) 2026 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## osv-scalibr

The regexes that pass the test from the Veles secret detectors, `veles/secrets/*/*.go` less their
tests, taken after gitleaks' and betterleaks', at commit
`e695f1e559c7da939620cf03335c0a5bf1689df7`: <https://github.com/google/osv-scalibr>.
Copyright 2026 Google LLC, under the Apache License, Version 2.0, whose text is in
[LICENSE-APACHE](LICENSE-APACHE). The project has no NOTICE file.
