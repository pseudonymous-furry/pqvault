# pqvault

A Rust terminal password manager prototype with:
- per-user PQ key bundles
- ML-KEM wrapped vault keys
- ML-DSA vault signing
- generated passwords using the full printable ASCII set
- red-team-friendly confirmation flow for deletions
- encrypted file handling and zeroized secret buffers

This is not production software. It is a serious prototype meant for adversarial environments, where “simple mistakes” tend to become incident reports.
