#!/usr/bin/env python3
"""
=====================================================================================
  KEYFORGE  --  A Full-Featured Password Generator
=====================================================================================

  License      : MIT — see LICENSE. Free to use, modify, and distribute; just
                  keep the copyright notice and credit @anxntbhardwaj.
  Run it with  : python main.py

  FEATURES
  --------
   - Adjustable password length (slider + spinbox, synced, 4-128 characters)
   - Character-set toggles: Uppercase, Lowercase, Digits, Symbols
   - "Exclude ambiguous characters" (l, 1, I, O, 0, etc.) for readability
   - Custom character exclusion box (exclude any characters you don't want)
   - Guaranteed inclusion: at least one character from every selected set
   - Cryptographically secure randomness via Python's `secrets` module
     (never the plain `random` module -- that matters for real passwords)
   - Live strength meter (entropy-based) with color-coded bar and label
   - Passphrase mode: memorable diceword-style passphrases (e.g.
     "correct-horse-battery-staple42!") with adjustable word count
   - Batch generation: produce many passwords at once
   - One-click copy to clipboard with visual confirmation
   - Session history panel (in-memory only, never written to disk, for
     security) with copy / clear
   - Optional export of the current batch to a plain-text file (explicit
     user action only, with an on-screen security warning)
   - Light & Dark themes

=====================================================================================
"""

import os
import math
import string
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "KeyForge"
APP_AUTHOR = "@anxntbhardwaj"
APP_VERSION = "1.0.0"

THEMES = {
    "Light": {
        "bg": "#f4f5f7", "panel": "#ffffff", "text": "#1c1c1e", "subtext": "#6e6e73",
        "accent": "#4361ee", "accent_hover": "#3a56d4", "border": "#e0e0e6",
        "row_alt": "#f0f1f5", "selected": "#dbe4ff", "entry_bg": "#ffffff",
        "danger": "#e53935", "display_bg": "#1c1c1e", "display_fg": "#ffffff",
        "weak": "#e53935", "fair": "#ff9800", "good": "#ffc107", "strong": "#4caf50", "vstrong": "#2e7d32",
    },
    "Dark": {
        "bg": "#1a1b21", "panel": "#24252c", "text": "#f1f1f4", "subtext": "#9a9ba3",
        "accent": "#6c8bff", "accent_hover": "#8aa0ff", "border": "#33343d",
        "row_alt": "#1f2027", "selected": "#333a5c", "entry_bg": "#2c2d36",
        "danger": "#ff6b6b", "display_bg": "#0e0f13", "display_fg": "#ffffff",
        "weak": "#ff6b6b", "fair": "#ffa94d", "good": "#ffd43b", "strong": "#69db7c", "vstrong": "#40c057",
    },
}

AMBIGUOUS_CHARS = set("lI1O0oB8|`'\";:,.")
SYMBOL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>?/~"

# Small built-in wordlist for passphrase mode (EFF-style, hand-picked common
# words -- not the full EFF long list, but plenty of entropy for the mode's
# purpose and keeps the app dependency-free / single-file).
WORDLIST = """
apple bridge cactus dagger eagle forest galaxy harbor island jungle
kettle lantern meadow needle orange puzzle quartz river summit tiger
umbrella velvet willow xenon yonder zephyr anchor breeze canyon desert
ember flame garden hollow ivory jasper kernel lumber marble nectar
opal pebble quiver ribbon shadow talon urchin vortex walnut yield
badge cipher domino ferret glider hazel ingot jockey knight liquid
mango nomad orchid piston quokka ranger sable timber utopia vapor
wander yeoman zircon amber blaze comet drift ecliptic falcon glacier
```
""".split()
WORDLIST = [w for w in WORDLIST if w.isalpha()]


# ---------------------------------------------------------------------------------
# 1. PASSWORD GENERATION LOGIC (pure functions, no UI dependency)
# ---------------------------------------------------------------------------------

def build_charset(use_upper, use_lower, use_digits, use_symbols,
                   exclude_ambiguous, custom_exclude=""):
    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(SYMBOL_CHARS)

    exclude = set(custom_exclude)
    if exclude_ambiguous:
        exclude |= AMBIGUOUS_CHARS

    cleaned_pools = []
    for pool in pools:
        cleaned = "".join(ch for ch in pool if ch not in exclude)
        if cleaned:
            cleaned_pools.append(cleaned)
    return cleaned_pools


def generate_password(length, use_upper, use_lower, use_digits, use_symbols,
                       exclude_ambiguous=True, custom_exclude=""):
    pools = build_charset(use_upper, use_lower, use_digits, use_symbols,
                           exclude_ambiguous, custom_exclude)
    if not pools:
        raise ValueError("Select at least one character type.")

    all_chars = "".join(pools)
    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)} to include every selected type.")

    # Guarantee at least one char from each selected pool, fill the rest
    # randomly, then shuffle -- all using the CSPRNG `secrets` module.
    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]

    # Fisher-Yates shuffle using secrets for unbiased, secure ordering.
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def generate_passphrase(word_count=4, separator="-", capitalize=True,
                         append_number=True, append_symbol=True):
    words = [secrets.choice(WORDLIST) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    if append_number:
        phrase += str(secrets.randbelow(90) + 10)
    if append_symbol:
        phrase += secrets.choice("!@#$%&*")
    return phrase


def estimate_entropy_bits(password, pool_size_hint=None):
    """Rough Shannon-style entropy estimate: log2(pool_size) * length, using
    the actual distinct character categories present as the pool estimate
    when no explicit pool size is provided."""
    if pool_size_hint:
        pool = pool_size_hint
    else:
        pool = 0
        if any(c in string.ascii_lowercase for c in password):
            pool += 26
        if any(c in string.ascii_uppercase for c in password):
            pool += 26
        if any(c in string.digits for c in password):
            pool += 10
        if any(c in SYMBOL_CHARS for c in password):
            pool += len(SYMBOL_CHARS)
        pool = pool or 1
    if not password:
        return 0.0
    return len(password) * math.log2(pool)


def strength_label(bits):
    if bits < 28:
        return "Very Weak", "weak", 0.15
    if bits < 40:
        return "Weak", "weak", 0.3
    if bits < 60:
        return "Fair", "fair", 0.5
    if bits < 80:
        return "Good", "good", 0.7
    if bits < 100:
        return "Strong", "strong", 0.88
    return "Very Strong", "vstrong", 1.0


# ---------------------------------------------------------------------------------
# 2. MAIN APPLICATION
# ---------------------------------------------------------------------------------

class KeyForgeApp:
    def __init__(self, root):
        self.root = root
        self.theme_name = "Light"
        self.colors = THEMES[self.theme_name]
        self.history = []       # in-memory only, on purpose (security)
        self.batch_results = []
        self.mode = "password"  # "password" or "passphrase"

        self._configure_root()
        self._build_menu()
        self._build_layout()
        self._apply_theme()
        self.generate()

    # -- Root -----------------------------------------------------------------

    def _configure_root(self):
        self.root.title(f"{APP_NAME}  —  Password Generator  ·  by {APP_AUTHOR}")
        self.root.geometry("880x680")
        self.root.minsize(760, 600)

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Batch to Text File...", command=self.export_batch)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Theme (Light/Dark)", command=self.toggle_theme)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=f"About {APP_NAME}", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)
        self.root.bind("<Control-g>", lambda e: self.generate())
        self.root.bind("<Control-c>", lambda e: self.copy_current())

    # -- Layout -----------------------------------------------------------------

    def _build_layout(self):
        c = self.colors
        self.outer = tk.Frame(self.root, bg=c["bg"])
        self.outer.pack(fill="both", expand=True)

        header = tk.Frame(self.outer, bg=c["bg"])
        header.pack(fill="x", padx=20, pady=(16, 8))
        self.title_label = tk.Label(header, text=f"🔐 {APP_NAME}", font=("Segoe UI", 19, "bold"),
                                      bg=c["bg"], fg=c["text"])
        self.title_label.pack(side="left")
        self.brand_label = tk.Label(header, text=f"by {APP_AUTHOR}", font=("Segoe UI", 9, "italic"),
                                      bg=c["bg"], fg=c["subtext"])
        self.brand_label.pack(side="left", padx=(8, 0), pady=(6, 0))
        self.theme_btn = tk.Button(header, text="🌙", command=self.toggle_theme,
                                     font=("Segoe UI", 12), relief="flat", bd=0,
                                     cursor="hand2", padx=10, pady=4)
        self.theme_btn.pack(side="right")

        self.notebook = ttk.Notebook(self.outer)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        self.gen_tab = tk.Frame(self.notebook, bg=c["bg"])
        self.history_tab = tk.Frame(self.notebook, bg=c["bg"])
        self.notebook.add(self.gen_tab, text="  Generator  ")
        self.notebook.add(self.history_tab, text="  Session History  ")

        self._build_generator_tab()
        self._build_history_tab()

    # -- Generator tab ------------------------------------------------------------

    def _build_generator_tab(self):
        c = self.colors
        body = tk.Frame(self.gen_tab, bg=c["bg"])
        body.pack(fill="both", expand=True)

        # ---- Mode switch ----
        mode_frame = tk.Frame(body, bg=c["bg"])
        mode_frame.pack(fill="x", pady=(0, 10))
        self.mode_var = tk.StringVar(value="password")
        for label, val in [("🔑 Random Password", "password"), ("📝 Passphrase", "passphrase")]:
            rb = tk.Radiobutton(mode_frame, text=label, variable=self.mode_var, value=val,
                                  command=self._on_mode_change, bg=c["bg"], fg=c["text"],
                                  selectcolor=c["panel"], activebackground=c["bg"],
                                  font=("Segoe UI", 10, "bold"), indicatoron=True)
            rb.pack(side="left", padx=(0, 16))

        # ---- Display / output ----
        self.display_frame = tk.Frame(body, bg=c["display_bg"])
        self.display_frame.pack(fill="x", pady=(0, 6))
        self.password_var = tk.StringVar()
        self.password_display = tk.Entry(self.display_frame, textvariable=self.password_var,
                                           font=("Consolas", 20, "bold"), bg=c["display_bg"],
                                           fg=c["display_fg"], relief="flat", justify="center",
                                           readonlybackground=c["display_bg"], state="readonly",
                                           insertbackground=c["display_fg"])
        self.password_display.pack(fill="x", padx=16, pady=18, ipady=6)

        action_row = tk.Frame(body, bg=c["bg"])
        action_row.pack(fill="x", pady=(0, 10))
        self.generate_btn = tk.Button(action_row, text="⟳ Generate  (Ctrl+G)", command=self.generate,
                                        font=("Segoe UI", 11, "bold"), relief="flat", bd=0,
                                        cursor="hand2", padx=16, pady=10)
        self.generate_btn.pack(side="left")
        self.copy_btn = tk.Button(action_row, text="⧉ Copy  (Ctrl+C)", command=self.copy_current,
                                    font=("Segoe UI", 11, "bold"), relief="flat", bd=0,
                                    cursor="hand2", padx=16, pady=10)
        self.copy_btn.pack(side="left", padx=(8, 0))
        self.copy_feedback = tk.Label(action_row, text="", font=("Segoe UI", 9, "italic"),
                                        bg=c["bg"], fg=c["strong"])
        self.copy_feedback.pack(side="left", padx=(10, 0))

        # ---- Strength meter ----
        strength_frame = tk.Frame(body, bg=c["bg"])
        strength_frame.pack(fill="x", pady=(0, 14))
        self.strength_label_widget = tk.Label(strength_frame, text="Strength: —",
                                                 font=("Segoe UI", 10, "bold"),
                                                 bg=c["bg"], fg=c["text"])
        self.strength_label_widget.pack(anchor="w")
        self.strength_canvas = tk.Canvas(strength_frame, height=10, bg=c["row_alt"],
                                           highlightthickness=0)
        self.strength_canvas.pack(fill="x", pady=(4, 0))

        # ---- Options: two-column area, mode-dependent ----
        self.options_container = tk.Frame(body, bg=c["panel"])
        self.options_container.pack(fill="both", expand=True)

        self.password_options_frame = tk.Frame(self.options_container, bg=c["panel"])
        self.passphrase_options_frame = tk.Frame(self.options_container, bg=c["panel"])
        self._build_password_options(self.password_options_frame)
        self._build_passphrase_options(self.passphrase_options_frame)
        self.password_options_frame.pack(fill="both", expand=True, padx=16, pady=16)

        # ---- Batch generation ----
        batch_frame = tk.Frame(body, bg=c["bg"])
        batch_frame.pack(fill="x", pady=(12, 0))
        tk.Label(batch_frame, text="Batch count:", font=("Segoe UI", 10),
                  bg=c["bg"], fg=c["text"]).pack(side="left")
        self.batch_count_var = tk.IntVar(value=5)
        tk.Spinbox(batch_frame, from_=1, to=100, textvariable=self.batch_count_var,
                    width=5, font=("Segoe UI", 10)).pack(side="left", padx=(6, 10))
        tk.Button(batch_frame, text="Generate Batch", command=self.generate_batch,
                   font=("Segoe UI", 10, "bold"), relief="flat", bd=0, cursor="hand2",
                   padx=12, pady=6).pack(side="left")

    def _build_password_options(self, parent):
        c = self.colors
        tk.Label(parent, text="LENGTH", font=("Segoe UI", 9, "bold"),
                  bg=c["panel"], fg=c["subtext"]).grid(row=0, column=0, sticky="w")
        self.length_var = tk.IntVar(value=16)
        length_row = tk.Frame(parent, bg=c["panel"])
        length_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(2, 14))
        self.length_scale = tk.Scale(length_row, from_=4, to=128, orient="horizontal",
                                       variable=self.length_var, showvalue=False,
                                       bg=c["panel"], fg=c["text"], troughcolor=c["row_alt"],
                                       highlightthickness=0, command=lambda v: self._sync_length_spin())
        self.length_scale.pack(side="left", fill="x", expand=True)
        self.length_spin = tk.Spinbox(length_row, from_=4, to=128, width=5,
                                        textvariable=self.length_var, font=("Segoe UI", 10),
                                        command=self._sync_length_scale)
        self.length_spin.pack(side="left", padx=(10, 0))

        tk.Label(parent, text="CHARACTER TYPES", font=("Segoe UI", 9, "bold"),
                  bg=c["panel"], fg=c["subtext"]).grid(row=2, column=0, sticky="w")
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        check_frame = tk.Frame(parent, bg=c["panel"])
        check_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 14))
        for label, var in [("A-Z Uppercase", self.use_upper), ("a-z Lowercase", self.use_lower),
                             ("0-9 Digits", self.use_digits), ("!@# Symbols", self.use_symbols)]:
            tk.Checkbutton(check_frame, text=label, variable=var, bg=c["panel"], fg=c["text"],
                             selectcolor=c["panel"], activebackground=c["panel"],
                             font=("Segoe UI", 10)).pack(side="left", padx=(0, 14))

        tk.Label(parent, text="EXCLUSIONS", font=("Segoe UI", 9, "bold"),
                  bg=c["panel"], fg=c["subtext"]).grid(row=4, column=0, sticky="w")
        excl_frame = tk.Frame(parent, bg=c["panel"])
        excl_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        self.exclude_ambiguous = tk.BooleanVar(value=True)
        tk.Checkbutton(excl_frame, text="Exclude ambiguous characters (l, 1, I, O, 0, ...)",
                         variable=self.exclude_ambiguous, bg=c["panel"], fg=c["text"],
                         selectcolor=c["panel"], activebackground=c["panel"],
                         font=("Segoe UI", 10)).pack(anchor="w")
        custom_row = tk.Frame(parent, bg=c["panel"])
        custom_row.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        tk.Label(custom_row, text="Custom exclude:", font=("Segoe UI", 10),
                  bg=c["panel"], fg=c["text"]).pack(side="left")
        self.custom_exclude_var = tk.StringVar()
        tk.Entry(custom_row, textvariable=self.custom_exclude_var, font=("Segoe UI", 10),
                  bg=c["entry_bg"], fg=c["text"], relief="flat", highlightthickness=1,
                  highlightbackground=c["border"], width=20).pack(side="left", padx=(8, 0))

        parent.grid_columnconfigure(0, weight=1)

    def _build_passphrase_options(self, parent):
        c = self.colors
        tk.Label(parent, text="WORD COUNT", font=("Segoe UI", 9, "bold"),
                  bg=c["panel"], fg=c["subtext"]).grid(row=0, column=0, sticky="w")
        self.word_count_var = tk.IntVar(value=4)
        word_row = tk.Frame(parent, bg=c["panel"])
        word_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(2, 14))
        tk.Scale(word_row, from_=3, to=8, orient="horizontal", variable=self.word_count_var,
                  bg=c["panel"], fg=c["text"], troughcolor=c["row_alt"],
                  highlightthickness=0).pack(fill="x", expand=True)

        tk.Label(parent, text="SEPARATOR", font=("Segoe UI", 9, "bold"),
                  bg=c["panel"], fg=c["subtext"]).grid(row=2, column=0, sticky="w")
        self.separator_var = tk.StringVar(value="-")
        sep_combo = ttk.Combobox(parent, textvariable=self.separator_var,
                                   values=["-", "_", ".", " ", ""], state="readonly",
                                   font=("Segoe UI", 10), width=8)
        sep_combo.grid(row=3, column=0, sticky="w", pady=(2, 14))

        opt_frame = tk.Frame(parent, bg=c["panel"])
        opt_frame.grid(row=4, column=0, columnspan=2, sticky="ew")
        self.capitalize_var = tk.BooleanVar(value=True)
        self.append_number_var = tk.BooleanVar(value=True)
        self.append_symbol_var = tk.BooleanVar(value=True)
        for label, var in [("Capitalize words", self.capitalize_var),
                             ("Append number", self.append_number_var),
                             ("Append symbol", self.append_symbol_var)]:
            tk.Checkbutton(opt_frame, text=label, variable=var, bg=c["panel"], fg=c["text"],
                             selectcolor=c["panel"], activebackground=c["panel"],
                             font=("Segoe UI", 10)).pack(anchor="w", pady=2)

        note = tk.Label(parent, text="Passphrases from a built-in wordlist are easier to\n"
                                       "remember and, with enough words, very strong.",
                          font=("Segoe UI", 9, "italic"), bg=c["panel"], fg=c["subtext"],
                          justify="left")
        note.grid(row=5, column=0, columnspan=2, sticky="w", pady=(14, 0))

        parent.grid_columnconfigure(0, weight=1)

    def _sync_length_spin(self):
        pass  # IntVar is shared, spinbox updates automatically

    def _sync_length_scale(self):
        pass  # IntVar is shared, scale updates automatically

    def _on_mode_change(self):
        self.mode = self.mode_var.get()
        if self.mode == "password":
            self.passphrase_options_frame.pack_forget()
            self.password_options_frame.pack(fill="both", expand=True, padx=16, pady=16)
        else:
            self.password_options_frame.pack_forget()
            self.passphrase_options_frame.pack(fill="both", expand=True, padx=16, pady=16)
        self.generate()

    # -- History tab --------------------------------------------------------------

    def _build_history_tab(self):
        c = self.colors
        frame = tk.Frame(self.history_tab, bg=c["bg"])
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        note = tk.Label(frame,
                          text="🔒 Session history only -- nothing here is ever written to disk. "
                               "It clears when you close the app.",
                          font=("Segoe UI", 9, "italic"), bg=c["bg"], fg=c["subtext"],
                          anchor="w", justify="left")
        note.pack(fill="x", pady=(0, 8))

        list_frame = tk.Frame(frame, bg=c["panel"])
        list_frame.pack(fill="both", expand=True)
        self.history_listbox = tk.Listbox(list_frame, font=("Consolas", 11), bg=c["entry_bg"],
                                            fg=c["text"], relief="flat", highlightthickness=1,
                                            highlightbackground=c["border"],
                                            selectbackground=c["selected"], activestyle="none")
        self.history_listbox.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.history_listbox.yview)
        self.history_listbox.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.history_listbox.bind("<Double-1>", self._copy_history_item)

        btn_row = tk.Frame(frame, bg=c["bg"])
        btn_row.pack(fill="x", pady=(8, 0))
        tk.Button(btn_row, text="Copy Selected", command=self._copy_history_item,
                   font=("Segoe UI", 10), relief="flat", bd=0, cursor="hand2",
                   padx=12, pady=6).pack(side="left")
        tk.Button(btn_row, text="Clear History", command=self._clear_history,
                   font=("Segoe UI", 10), relief="flat", bd=0, cursor="hand2",
                   padx=12, pady=6).pack(side="left", padx=(8, 0))

    # -- Generation actions ---------------------------------------------------------

    def generate(self):
        try:
            if self.mode == "password":
                pw = generate_password(
                    length=self.length_var.get(),
                    use_upper=self.use_upper.get(), use_lower=self.use_lower.get(),
                    use_digits=self.use_digits.get(), use_symbols=self.use_symbols.get(),
                    exclude_ambiguous=self.exclude_ambiguous.get(),
                    custom_exclude=self.custom_exclude_var.get(),
                )
            else:
                pw = generate_passphrase(
                    word_count=self.word_count_var.get(),
                    separator=self.separator_var.get(),
                    capitalize=self.capitalize_var.get(),
                    append_number=self.append_number_var.get(),
                    append_symbol=self.append_symbol_var.get(),
                )
        except ValueError as e:
            messagebox.showwarning(APP_NAME, str(e))
            return

        self.password_var.set(pw)
        self._add_to_history(pw)
        self._update_strength(pw)
        self.copy_feedback.configure(text="")

    def generate_batch(self):
        count = self.batch_count_var.get()
        results = []
        try:
            for _ in range(count):
                if self.mode == "password":
                    pw = generate_password(
                        length=self.length_var.get(),
                        use_upper=self.use_upper.get(), use_lower=self.use_lower.get(),
                        use_digits=self.use_digits.get(), use_symbols=self.use_symbols.get(),
                        exclude_ambiguous=self.exclude_ambiguous.get(),
                        custom_exclude=self.custom_exclude_var.get(),
                    )
                else:
                    pw = generate_passphrase(
                        word_count=self.word_count_var.get(),
                        separator=self.separator_var.get(),
                        capitalize=self.capitalize_var.get(),
                        append_number=self.append_number_var.get(),
                        append_symbol=self.append_symbol_var.get(),
                    )
                results.append(pw)
                self._add_to_history(pw)
        except ValueError as e:
            messagebox.showwarning(APP_NAME, str(e))
            return

        self.batch_results = results
        if results:
            self.password_var.set(results[-1])
            self._update_strength(results[-1])
        self.notebook.select(1)
        messagebox.showinfo(APP_NAME, f"Generated {len(results)} entries -- see Session History.")

    def _update_strength(self, password):
        bits = estimate_entropy_bits(password)
        label, tag, fraction = strength_label(bits)
        c = self.colors
        self.strength_label_widget.configure(
            text=f"Strength: {label}   (~{bits:.0f} bits of entropy)", fg=c[tag])
        self._draw_strength_bar(fraction, c[tag])

    def _draw_strength_bar(self, fraction, color):
        self.strength_canvas.delete("all")
        self.strength_canvas.update_idletasks()
        width = self.strength_canvas.winfo_width() or 600
        height = 10
        self.strength_canvas.create_rectangle(0, 0, width, height,
                                                 fill=self.colors["row_alt"], outline="")
        self.strength_canvas.create_rectangle(0, 0, max(4, int(width * fraction)), height,
                                                 fill=color, outline="")

    # -- Clipboard / history ----------------------------------------------------------

    def copy_current(self):
        pw = self.password_var.get()
        if not pw:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        self.copy_feedback.configure(text="Copied to clipboard ✓")
        self.root.after(2000, lambda: self.copy_feedback.configure(text=""))

    def _add_to_history(self, pw):
        self.history.append(pw)
        self.history_listbox.insert(tk.END, pw)
        self.history_listbox.see(tk.END)

    def _copy_history_item(self, event=None):
        sel = self.history_listbox.curselection()
        if not sel:
            return
        pw = self.history_listbox.get(sel[0])
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        messagebox.showinfo(APP_NAME, "Copied to clipboard.")

    def _clear_history(self):
        if not self.history:
            return
        if messagebox.askyesno(APP_NAME, "Clear session history? This cannot be undone."):
            self.history.clear()
            self.history_listbox.delete(0, tk.END)

    def export_batch(self):
        if not self.history:
            messagebox.showinfo(APP_NAME, "No passwords generated yet this session.")
            return
        proceed = messagebox.askyesno(
            APP_NAME,
            "This will save your generated passwords as PLAIN TEXT on disk.\n\n"
            "Anyone with access to this file can read them. Continue?")
        if not proceed:
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                              filetypes=[("Text file", "*.txt")],
                                              initialfile="keyforge_passwords.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{APP_NAME} — generated passwords (session export)\n")
            f.write("Keep this file secure or delete it after use.\n")
            f.write("=" * 50 + "\n\n")
            for pw in self.history:
                f.write(pw + "\n")
        messagebox.showinfo(APP_NAME, f"Exported {len(self.history)} entries to:\n{path}")

    # -- Theme ----------------------------------------------------------------------

    def toggle_theme(self):
        self.theme_name = "Dark" if self.theme_name == "Light" else "Light"
        self.colors = THEMES[self.theme_name]
        self._rebuild_all()

    def _rebuild_all(self):
        current_mode = self.mode_var.get() if hasattr(self, "mode_var") else "password"
        current_history = list(self.history)
        # _build_layout() always creates a brand-new self.outer frame, so the
        # OLD one must be fully destroyed here first -- destroying only its
        # children left an empty leftover frame stacked in the window, which
        # is what caused the layout to break/disappear on theme toggle.
        if hasattr(self, "outer"):
            self.outer.destroy()
        self._build_layout()
        self._apply_theme()
        self.mode_var.set(current_mode)
        self._on_mode_change()
        self.history = current_history
        for pw in self.history:
            self.history_listbox.insert(tk.END, pw)
        self.generate()

    def _apply_theme(self):
        c = self.colors
        self.root.configure(bg=c["bg"])
        self.outer.configure(bg=c["bg"])
        self.title_label.configure(bg=c["bg"], fg=c["text"])
        self.brand_label.configure(bg=c["bg"], fg=c["subtext"])
        self.theme_btn.configure(bg=c["bg"], fg=c["text"],
                                   text="🌙" if self.theme_name == "Light" else "☀")
        self.generate_btn.configure(bg=c["accent"], fg="white", activebackground=c["accent_hover"],
                                      activeforeground="white")
        self.copy_btn.configure(bg=c["row_alt"], fg=c["text"], activebackground=c["selected"])
        self.gen_tab.configure(bg=c["bg"])
        self.history_tab.configure(bg=c["bg"])

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook", background=c["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=c["row_alt"], foreground=c["text"],
                          padding=[14, 8], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", c["accent"])],
                   foreground=[("selected", "white")])
        style.configure("TCombobox", fieldbackground=c["entry_bg"], background=c["entry_bg"],
                          foreground=c["text"])

    # -- Help -----------------------------------------------------------------------

    def show_about(self):
        text = (
            f"{APP_NAME}  v{APP_VERSION}\n\n"
            "A full-featured password generator with a strength meter,\n"
            "passphrase mode, and secure random generation via Python's\n"
            "`secrets` module -- built with pure Python (Tkinter).\n\n"
            "History lives only in memory for this session and is never\n"
            "written to disk unless you explicitly export it.\n\n"
            f"Developed by {APP_AUTHOR}\n"
        )
        messagebox.showinfo(f"About {APP_NAME}", text)


def main():
    root = tk.Tk()
    KeyForgeApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
