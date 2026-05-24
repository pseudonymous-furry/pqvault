# pqvault

A Rust terminal password manager prototype with:
- per-user PQ key bundles
- ML-KEM wrapped vault keys
- ML-DSA vault signing
- generated passwords using the full printable ASCII set
- confirmation flow for deletions
- encrypted file handling and zeroized secret buffers

This is not production software. It is a serious prototype meant for adversarial environments, where “simple mistakes” tend to become incident reports.

Please do not use this in production.. If you do use it for anything valuable, I am not responsible for any damage that may result from that questionable decision.

Please do not trust pseudonymous furries on the internet with your passwords.
Only trust yourself with your passwords.
