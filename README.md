# PrivnoteRS

Rust binary to post to [Privnote](https://privnote.com/) and return the secret URL.

Takes stdin (either from a piped input, or entering text followed by ^D), and returns the URL to stdout

```bash
❯ echo "secret stuff" | privnoters
https://privnote.com/r9RvrgM9#1Aa5Dzqcm

❯ privnoters
This is some text I entered
^D
https://privnote.com/EnKq6nkh#M72QwfIXg
```
