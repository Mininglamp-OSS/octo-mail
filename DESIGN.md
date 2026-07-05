---
version: alpha
name: octo-mail — Monochrome
description: >-
  The visual identity for octo-mail's product surfaces (webmail and any future
  UI). An enterprise-grade, near-achromatic system: a neutral zinc ramp does all
  the layout work, and emphasis is carried by near-black / near-white fills,
  type weight, and contrast — not by hue. Compact information density.
  Light-first with an automatic dark mapping via prefers-color-scheme.

colors:
  # Emphasis — the "accent" is contrast, not color. Near-black in light,
  # near-white in dark; on-accent flips accordingly. `primary` and `accent` are
  # the same near-black ink (primary is the canonical name; accent reads better
  # in prose).
  primary:        "#18181b"   # primary interactive color (= accent)
  accent:         "#18181b"   # primary fills, active state, focus, unread dot
  accent-strong:  "#000000"   # hover/pressed
  on-accent:      "#ffffff"   # text/icon on an accent fill
  focus:          "#18181b"   # keyboard focus ring

  # Functional (used narrowly)
  danger:         "#c0392b"   # errors, junk, send failure
  danger-ghost:   "#fbecea"

  # Surfaces (low -> high elevation)
  bg:             "#fafafa"   # app canvas
  bg-sunken:      "#f4f4f5"   # sidebar, inputs
  bg-panel:       "#ffffff"   # list & reader panels, cards, modals
  bg-hover:       "#f4f4f5"   # row/nav hover
  bg-active:      "#efeff1"   # selected row/nav (neutral, not tinted)

  # Lines
  border:         "#ececee"
  border-soft:    "#f2f2f3"
  border-strong:  "#d9d9dd"

  # Text (high -> low emphasis) — pure neutral ramp
  text:           "#0a0a0b"
  text-soft:      "#5c5c66"
  text-faint:     "#9a9aa4"

  # Neutral avatar (no hue)
  avatar-bg:      "#e6e6e9"
  avatar-fg:      "#52525b"

  # Dark theme (applied under prefers-color-scheme: dark)
  dark-accent:        "#fafafa"
  dark-accent-strong: "#ffffff"
  dark-on-accent:     "#0a0a0b"
  dark-focus:         "#d4d4d8"
  dark-bg:            "#0a0a0b"
  dark-bg-sunken:     "#0d0d0f"
  dark-bg-panel:      "#121214"
  dark-bg-hover:      "#19191c"
  dark-bg-active:     "#202024"
  dark-border:        "#222226"
  dark-border-strong: "#34343a"
  dark-text:          "#fafafa"
  dark-text-soft:     "#a1a1aa"
  dark-text-faint:    "#6b6b74"
  dark-avatar-bg:     "#26262b"
  dark-avatar-fg:     "#b0b0ba"

typography:
  fontFamilyUI:   'ui-sans-serif, -apple-system, "Segoe UI", system-ui, "Helvetica Neue", sans-serif'
  fontFamilyMono: 'ui-monospace, "SF Mono", "JetBrains Mono", "Menlo", "Consolas", monospace'

  display:      # reader subject headline
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "19px"
    fontWeight: 680
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  title:        # pane headers ("Inbox")
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "15px"
    fontWeight: 680
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  body:         # base UI text
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
  body-read:    # reading pane
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "13.5px"
    fontWeight: 400
    lineHeight: 1.7
  emphasis:     # unread sender/subject + button labels
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "13px"
    fontWeight: 700
    lineHeight: 1.4
  label-caps:   # form labels, "MAILBOXES"
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "10px"
    fontWeight: 650
    lineHeight: 1.4
    letterSpacing: "0.05em"
  meta:         # timestamps, addresses, counts, status
    fontFamily: "{typography.fontFamilyMono}"
    fontSize: "10px"
    fontWeight: 400
    lineHeight: 1.4

rounded:
  xs:   "4px"
  sm:   "6px"
  md:   "9px"
  lg:   "13px"
  pill: "999px"

spacing:
  # 4px grid.
  s1: "4px"
  s2: "8px"
  s3: "12px"
  s4: "16px"
  s5: "20px"
  s6: "24px"
  s8: "32px"
  sidebar-width: "212px"
  list-width: "344px"

components:
  button-primary:      # the single strong action per view
    backgroundColor: "{colors.accent}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.sm}"
    padding: "9px 20px"
    typography: "{typography.emphasis}"
  button-primary-hover:
    backgroundColor: "{colors.accent-strong}"
    textColor: "{colors.on-accent}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.text-soft}"
    rounded: "{rounded.sm}"
    padding: "9px 14px"
  button-ghost-hover:
    backgroundColor: "{colors.bg-hover}"
    textColor: "{colors.text}"
  input:
    backgroundColor: "{colors.bg-panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.sm}"
    padding: "9px 11px"
  input-focus:
    backgroundColor: "{colors.bg-panel}"
    textColor: "{colors.text}"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.text-soft}"
    rounded: "{rounded.sm}"
    padding: "6px 8px"
  nav-item-active:
    backgroundColor: "{colors.bg-active}"
    textColor: "{colors.text}"
  card:
    backgroundColor: "{colors.bg-panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.lg}"
    padding: "32px"
  message-row:
    backgroundColor: "{colors.bg-panel}"
    textColor: "{colors.text}"
    padding: "8px 16px 8px 12px"
  message-row-active:
    backgroundColor: "{colors.bg-active}"
    textColor: "{colors.text}"
---

# octo-mail — Monochrome

## Overview

octo-mail is a change-log-centric mail server kernel. Its product surfaces should
read like a precise professional instrument — the register of Linear, Vercel, or
Hey, not a consumer inbox. The system is **Monochrome**: a near-achromatic zinc
neutral ramp carries the entire interface, and *emphasis is expressed through
contrast, not hue*.

Three rules define the identity:

- **The "accent" is near-black (near-white in dark), not a color.** The single
  strong action per view — Sign in, Compose, Send — is a solid near-black fill.
  Selection, focus, and the unread dot use the same near-black. There is no brand
  hue; introducing one would cheapen the result. Color appears only for genuinely
  functional signals (`danger` for errors/junk).
- **Density is enterprise-grade.** Rows are compact (~40px), the type scale is
  small (13px base, 10px metadata), and the panes are narrow so a screen shows
  ~14+ messages. Whitespace is deliberate, not generous.
- **Monospace is for machine facts.** Timestamps, addresses, counts, status
  lines, and section labels are set in the mono family — the visual tell that
  octo-mail is infrastructure, keeping prose and metadata legibly distinct.

The system is **light-first** but ships a full dark mapping applied automatically
via `prefers-color-scheme: dark`. Never hardcode a single theme's literal hex in
a component — reference tokens so both themes (and both accent polarities)
resolve.

## Colors

One neutral ramp, no hue. The neutrals do all the layout and hierarchy work;
"accent" is simply the darkest ink (or, in dark mode, the lightest).

- **`accent` (#18181b / dark #fafafa)** — the only strong fill: primary buttons,
  the active row's left bar, the unread dot, focus rings. `accent-strong` is its
  hover. Text on an accent fill uses `on-accent`, which flips to dark ink in dark
  mode so the light fill never glares.
- **Surfaces** stack by elevation: `bg` (canvas) → `bg-sunken` (sidebar, inputs)
  → `bg-panel` (list, reader, cards, modals). Hover and selection are the
  **neutral** `bg-hover` / `bg-active` — a slightly deeper gray, never a colored
  tint. Selection reads as "one step lifted," reinforced by the near-black
  accent bar, not by warmth.
- **Text** has exactly three neutral emphasis levels: `text` for content,
  `text-soft` for secondary labels and read (already-seen) rows, `text-faint`
  for metadata. Do not invent intermediate grays.
- **`danger`** is the only chromatic color, used narrowly: sign-in errors, the
  `junk` tag, send failures. Never decorative.
- **Avatars** are neutral (`avatar-bg` / `avatar-fg`) — no gradient, no hue —
  circles with uppercase initials.

Dark mode is a re-grounding, not an inversion: backgrounds go to true near-black
(`dark-bg` #0a0a0b), and the accent becomes near-white so the strongest element
is still the highest-contrast one.

Contrast: body text meets WCAG AA on its surface; `text-faint` is reserved for
non-essential metadata and may sit lighter. Accent fills always pair with the
matching `on-accent`.

## Typography

Two families, one small scale tuned for density. The UI family is the platform's
native sans (no web-font download — the product embeds in a single binary and
must render offline); the mono family carries all machine metadata.

- **`display`** — reader subject headline, one per screen.
- **`title`** — pane headers ("Inbox").
- **`emphasis` (weight 700)** — unread senders/subjects and button labels. Weight
  is the primary "unread" signal, paired with `text` color and the dot.
- **`body` / `body-read`** — UI text (13px) and the reading pane (13.5px / 1.7).
- **`label-caps`** — uppercase, tracked section labels.
- **`meta` (mono)** — timestamps, addresses, counts, "signed in", the sign-in
  tagline. Always pair with `font-variant-numeric: tabular-nums`.

Read list rows drop to `text-soft` + normal weight; unread rows use `text` +
`emphasis`. That weight/color shift is the primary read/unread cue; the dot is
secondary.

## Layout

A **fixed, compact three-pane shell**: sidebar (`sidebar-width` 212px) · message
list (`list-width` 344px) · flexible reader. Below 720px the two left panes
collapse and the reader fills the width.

All spacing derives from a **4px grid** (`s1`…`s8`). Rows are tight (8px vertical
padding, ~40px total) to maximize messages-per-screen; panes are separated by
`border` hairlines, not shadows. The reading pane caps at `72ch` for legibility.

## Elevation & Depth

Depth is expressed with hairline borders and three restrained shadow steps — the
monochrome palette makes heavy shadows look muddy, so they stay subtle:

- **Flat** — panels sit coplanar, divided by `border`.
- **`shadow-sm`** — resting fills (buttons).
- **`shadow-md`** — hover lift.
- **`shadow-lg`** — the sign-in card and compose modal (things that float). The
  compose scrim adds `backdrop-blur(3px)`.

In dark mode shadows deepen rather than disappear.

## Shapes

Corners come from a slightly tightened `rounded` scale (enterprise UIs read
sharper), matched to element size:

- **`xs` (4px)** — focus rounding, tiny tags.
- **`sm` (6px)** — the workhorse: buttons, inputs, nav items, rows.
- **`md` (9px)** — the brand mark tile.
- **`lg` (13px)** — cards and the compose modal (top corners only; it docks to
  the bottom edge).
- **`pill` (999px)** — avatars (circles) and scrollbar thumbs.

## Components

- **button-primary** — near-black fill, `on-accent` text, `sm` radius,
  `shadow-sm`. Hover → `accent-strong`. The only filled button; at most one per
  view (sign-in, compose-open, send).
- **button-ghost** — transparent, `text-soft`, hover fills `bg-hover`. Used for
  Discard and all icon buttons (refresh, sign-out, close).
- **input** — `bg-panel` fill, `border-strong` hairline; on focus the border goes
  `accent` with a faint 3px ring (a low-alpha mix of the accent).
- **nav-item** — quiet `text-soft` row; hover tints `bg-hover`; active gets the
  neutral `bg-active` + `text` label + a mono count. No colored badge.
- **message-row** — avatar · (sender + time) · subject · preview, with a
  near-black left bar and `bg-active` when selected, and a near-black unread dot
  (with a surface-matched halo) when unread. Unread = `emphasis` weight +
  `text`; read = normal weight + `text-soft`. Hover previews the bar in a neutral
  tone; active/focus resolves it to the accent.
- **card / compose** — `bg-panel`, `lg` radius, `shadow-lg`, float above the app.

Interactive elements (including the clickable nav items and message rows) are
keyboard-operable and show a keyboard-only focus ring (`:focus-visible`), never a
mouse-click outline. Transitions share a `cubic-bezier(.2,.7,.2,1)` easing and
respect `prefers-reduced-motion`.

## Do's and Don'ts

**Do**
- Reference tokens (`{colors.accent}`, `{spacing.s4}`) so light/dark and both
  accent polarities resolve and the 4px rhythm holds.
- Keep the interface neutral — express emphasis with the near-black fill, type
  weight, and contrast.
- Set all timestamps, addresses, counts, and status text in the mono family with
  `tabular-nums`.
- Separate panes with hairline borders; reserve shadows for floating surfaces.
- Signal unread with weight **and** color, not the dot alone.
- Keep density high: compact rows, small type, narrow panes.

**Don't**
- Introduce a brand hue, a gradient, or a colored selection tint — this system
  is monochrome; selection is a neutral step + a near-black bar.
- Hardcode a theme's literal hex in a component — it will break the other theme
  or the accent polarity.
- Invent intermediate grays between the three text levels or the surface steps.
- Put body copy in the mono family, or metadata in the sans family.
- Use color as the *only* differentiator for state (pair it with weight, an
  icon, or the accent bar), and never rely on a focus style that only shows on
  mouse click.
