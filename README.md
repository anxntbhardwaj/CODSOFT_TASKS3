# 🔐 KeyForge — Password Generator

**Developed by [@anxntbhardwaj](https://github.com/anxntbhardwaj)**

A pure-Python, single-file, desktop password generator built with Tkinter.
Cryptographically secure by design (uses Python's `secrets` module, never
`random`), with zero external dependencies.

## ✨ Features

- **Adjustable length** — slider + spinbox, 4 to 128 characters
- **Character-set toggles** — Uppercase, Lowercase, Digits, Symbols
- **Exclude ambiguous characters** (`l 1 I O 0 ...`) for easier reading/typing
- **Custom exclusion box** — block any specific characters you don't want
- **Guaranteed inclusion** — every selected character type is guaranteed to
  appear at least once, not left to chance
- **Cryptographically secure randomness** via Python's `secrets` module,
  including a secure Fisher-Yates shuffle — this is *real* password-grade
  randomness, not the `random` module
- **Live strength meter** — entropy-based, color-coded bar + label (Very
  Weak → Very Strong)
- **Passphrase mode** — memorable diceword-style phrases like
  `Correct-Horse-Battery-Staple42!`, with adjustable word count, separator,
  capitalization, and appended number/symbol
- **Batch generation** — generate up to 100 at once
- **One-click copy to clipboard** with visual confirmation
- **Session history** — kept in memory only, *never written to disk*, for
  security; clears automatically when you close the app
- **Optional export** — explicitly save the current session's passwords to a
  plain-text file, with an on-screen warning since it's stored unencrypted
- **Light & Dark themes**

## 🚀 Getting Started

Requires **Python 3.8+** with Tkinter (bundled with most Python installs; on
Debian/Ubuntu: `sudo apt install python3-tk`). No extra packages needed —
everything here is standard library.

```bash
python main.py
```

## ⌨️ Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+G` | Generate a new password/passphrase |
| `Ctrl+C` | Copy the current password to clipboard |
| Double-click a history row | Copy that entry |

## 🔒 A Note on Security

- Passwords are generated with `secrets`, Python's cryptographically secure
  random number generator — appropriate for real credentials.
- History is **in-memory only** and is never written to disk unless you
  explicitly choose **File → Export Batch to Text File**.
- If you do export, that file is **plain text** — store it somewhere secure
  or delete it once you've moved the passwords into a real password manager.

## 📄 License

Released under the **MIT License** — see [`LICENSE`](LICENSE). Free to use,
modify, and distribute; just keep the copyright notice and credit
**@anxntbhardwaj**.

---

Made with ☕ and Tkinter by **@anxntbhardwaj**

<img width="1920" height="966" alt="Python 3 9 12-07-2026 08_12_58" src="https://github.com/user-attachments/assets/1323d8ce-965b-407d-95cb-ec8e279e34b2" />
<img width="1920" height="966" alt="Python 3 9 12-07-2026 08_12_40" src="https://github.com/user-attachments/assets/6ddbaa4f-b35b-4b26-9848-23013305d8e6" />

