---
version: alpha
name: octo-mail — Ink & Tide
description: >-
  The visual identity for octo-mail's product surfaces (webmail and any future
  UI). A calm, tool-grade system: teal "tide" accents over slate "ink" neutrals,
  a 4px spacing grid, and monospace for machine metadata. Light-first with an
  automatic dark mapping via prefers-color-scheme.

colors:
  # Brand
  primary:        "#0d7d76"   # teal — actions, active state, links
  primary-strong: "#0a615c"   # hover/pressed accent
  primary-soft:   "#128f87"   # lighter accent for gradients
  primary-ghost:  "#e2f1ef"   # tinted accent wash (focus ring, active row)
  on-primary:     "#ffffff"   # text/icon on a primary fill
  danger:         "#b4453a"   # errors, junk, destructive
  danger-ghost:   "#f6e6e4"

  # Surfaces (low -> high elevation)
  bg:             "#eef1f4"   # app background
  bg-sunken:      "#e7ebef"   # sidebar, inputs
  bg-panel:       "#ffffff"   # list & reader panels, cards, modals
  bg-hover:       "#eef4f3"   # row/nav hover
  bg-active:      "#dcefec"   # selected row/nav tint

  # Lines
  border:         "#e4e8ec"   # standard hairline
  border-soft:    "#edf0f3"   # inner list dividers
  border-strong:  "#ccd3d9"   # modal edge, scrollbar thumb

  # Text (high -> low emphasis)
  text:           "#16262c"   # primary
  text-soft:      "#566871"   # secondary
  text-faint:     "#859399"   # tertiary / metadata

  # Dark theme (applied under prefers-color-scheme: dark)
  dark-primary:        "#2bb3a8"
  dark-primary-strong: "#52ccc1"
  dark-primary-ghost:  "#123330"
  dark-on-primary:     "#06201e"
  dark-bg:             "#0d1417"
  dark-bg-sunken:      "#0a1013"
  dark-bg-panel:       "#141d21"
  dark-bg-hover:       "#1a262b"
  dark-bg-active:      "#143430"
  dark-border:         "#222d33"
  dark-border-strong:  "#33434b"
  dark-text:           "#e8eef1"
  dark-text-soft:      "#a3b3ba"
  dark-text-faint:     "#6a7b83"

typography:
  # Families
  fontFamilyUI:   'ui-sans-serif, -apple-system, "Segoe UI", system-ui, "Helvetica Neue", sans-serif'
  fontFamilyMono: 'ui-monospace, "SF Mono", "JetBrains Mono", "Menlo", "Consolas", monospace'

  # Scale (used across the UI)
  display:
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "22px"
    fontWeight: 700
    lineHeight: 1.28
    letterSpacing: "-0.02em"
  title:
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "17px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  body:
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  body-read:
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "14.5px"
    fontWeight: 400
    lineHeight: 1.72
  emphasis:
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "13.5px"
    fontWeight: 720
    lineHeight: 1.4
  label-caps:
    fontFamily: "{typography.fontFamilyUI}"
    fontSize: "10.5px"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "0.06em"
  meta:
    fontFamily: "{typography.fontFamilyMono}"
    fontSize: "10.5px"
    fontWeight: 400
    lineHeight: 1.4

rounded:
  xs:   "5px"
  sm:   "8px"
  md:   "11px"
  lg:   "16px"
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
  sidebar-width: "244px"
  list-width: "372px"

components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.sm}"
    padding: "11px 22px"
    typography: "{typography.emphasis}"
  button-primary-hover:
    backgroundColor: "{colors.primary-strong}"
    textColor: "{colors.on-primary}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.text-soft}"
    rounded: "{rounded.sm}"
    padding: "10px 16px"
  button-ghost-hover:
    backgroundColor: "{colors.bg-hover}"
    textColor: "{colors.text}"
  input:
    backgroundColor: "{colors.bg-sunken}"
    textColor: "{colors.text}"
    rounded: "{rounded.sm}"
    padding: "10px 12px"
  input-focus:
    backgroundColor: "{colors.bg-panel}"
    textColor: "{colors.text}"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.text-soft}"
    rounded: "{rounded.sm}"
    padding: "9px 12px"
  nav-item-active:
    backgroundColor: "{colors.bg-active}"
    textColor: "{colors.primary-strong}"
  card:
    backgroundColor: "{colors.bg-panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.lg}"
    padding: "32px"
  message-row:
    backgroundColor: "{colors.bg-panel}"
    textColor: "{colors.text}"
    padding: "13px 20px 13px 16px"
  message-row-active:
    backgroundColor: "{colors.bg-active}"
    textColor: "{colors.text}"
---

# octo-mail — Ink & Tide

## Overview

octo-mail is a change-log-centric mail server kernel. Its product surfaces should
feel like precise, quiet instruments — closer to a well-built developer tool than
a consumer inbox. The system is named **Ink & Tide**: *ink* is the slate-neutral
foundation, *tide* is the single teal accent that carries every action and every
"you are here" signal.

Two rules give the identity its character:

- **One accent, used sparingly.** Teal appears only where the user acts or where
  the app answers "what's selected / unread / primary." Everything else is
  neutral. A screen with three teal things is right; a screen with ten is wrong.
- **Monospace is for machine facts.** Timestamps, addresses, counts, status
  lines, section labels — anything the *system* asserts rather than a human wrote
  — is set in the mono family. This is the visual tell that octo-mail is
  infrastructure, and it keeps prose and metadata legibly distinct.

The system is **light-first** but ships a full dark mapping applied automatically
via `prefers-color-scheme: dark`; never hardcode a single theme's literal hex in
a component — reference tokens so both themes resolve.

## Colors

The palette is one teal ramp over a cool-slate neutral ramp. Restraint is the
point: the neutrals do the layout work, the teal does the pointing.

- **`primary` (#0d7d76)** — the only brand color that touches interactive
  surfaces: primary buttons, the compose button, active nav/rows, links, focus
  rings (via `primary-ghost`), and the unread dot. `primary-strong` is its
  hover/pressed state; `primary-soft` is reserved for the brand-mark gradient.
- **Surfaces** stack by elevation: `bg` (app) → `bg-sunken` (sidebar, inputs) →
  `bg-panel` (list, reader, cards, modals). Hover and selection are the tinted
  `bg-hover` / `bg-active`, never a heavier neutral — selection reads as a *warm
  teal wash*, not a gray block.
- **Text** has three emphasis levels only. Use `text` for content, `text-soft`
  for secondary labels and read (already-seen) rows, `text-faint` for metadata.
  Do not invent intermediate grays.
- **`danger`** is used narrowly: sign-in errors, the `junk` tag, send failures.
  It is never a decorative color.

Dark theme is not an inversion — it's a re-grounding. Backgrounds go to deep
slate (`dark-bg` #0d1417), the accent *brightens* to `dark-primary` (#2bb3a8) so
it stays legible on dark, and text on a primary fill flips to the dark ink
`dark-on-primary` rather than white to keep the fill from glaring.

Contrast targets: body text meets WCAG AA on its surface; `text-faint` is for
non-essential metadata and is allowed to sit lighter. Accent fills always pair
with `on-primary` / `dark-on-primary`, not raw white in dark.

## Typography

Two families, one scale. The UI family is the platform's native sans (no web
font download — the product embeds in a single binary and must render offline);
the mono family carries all machine metadata.

- **`display`** — reader subject headline. Tight tracking, one per screen.
- **`title`** — pane headers ("Inbox").
- **`emphasis` (weight 720)** — unread senders/subjects and button labels. The
  heavy weight is how "unread" is signaled in the list, alongside color.
- **`body` / `body-read`** — UI text and the message reading pane; the reader
  uses the taller `body-read` line-height (1.72) for comfortable long reading.
- **`label-caps`** — uppercase, tracked section labels (form labels, "MAILBOXES").
- **`meta` (mono)** — timestamps, addresses, counts, the "signed in" status,
  the sign-in tagline. Always pair with `font-variant-numeric: tabular-nums` so
  times and counts align.

Read (already-seen) list rows drop to `text-soft` and normal weight; unread rows
use `text` + `emphasis`. That weight/color shift is the primary read/unread cue;
the teal dot is the secondary one.

## Layout

The app is a **fixed three-pane shell**: sidebar (`sidebar-width` 244px) ·
message list (`list-width` 372px) · flexible reader. Below 760px the two left
panes collapse and the reader takes the full width.

All spacing derives from a **4px grid** (`s1`…`s8`). Compose padding, gaps, and
margins must snap to these tokens — no ad-hoc `13px`/`18px` values except the
few intentional optical adjustments already baked into the message-row and
list-head components. Panels are separated by `border` hairlines, not shadows;
shadows are reserved for *floating* things (cards, modals).

Content width is capped for readability: the reading pane is `max-width: 74ch`.

## Elevation & Depth

Depth is expressed with three shadow steps and hairline borders, not heavy
blocks:

- **Flat** — panels sit at the same plane, divided by `border`.
- **`shadow-sm`** — resting buttons and small raised chips.
- **`shadow-md`** — hover lift on primary buttons.
- **`shadow-lg`** — the sign-in card and the compose modal (things that float
  above the app). The compose scrim adds a light `backdrop-blur(2px)`.

Primary fills carry a 1px inner top highlight (`inset 0 1px 0 rgba(255,255,255,.14)`)
for a subtle "lit from above" quality. In dark mode shadows deepen rather than
disappear.

## Shapes

Corners come from the `rounded` scale, matched to element size:

- **`xs` (5px)** — focus-ring rounding, tiny tags.
- **`sm` (8px)** — the workhorse: buttons, inputs, nav items, message-row
  affordances.
- **`md` (11px)** — the brand mark tile.
- **`lg` (16px)** — cards and the compose modal (top corners only, since it
  docks to the bottom edge).
- **`pill` (999px)** — avatars (as circles), nav count badges, scrollbar thumbs.

Avatars are always perfect circles filled with the teal→deep-teal gradient and
uppercase initials.

## Components

- **button-primary** — teal fill, `on-primary` text, `sm` radius, inner
  highlight, `shadow-sm`. Hover → `primary-strong`. This is the only filled
  button; there is at most one per view (sign-in, compose-open, send).
- **button-ghost** — transparent, `text-soft`, hover fills `bg-hover`. Used for
  Discard and all icon buttons (refresh, sign-out, close).
- **input** — `bg-sunken` fill, `border` hairline; on focus it lifts to
  `bg-panel`, the border goes `primary`, and a 3px `primary-ghost` ring appears.
- **nav-item** — quiet `text-soft` row; hover tints `bg-hover`; active gets the
  `bg-active` wash + `primary-strong` label + a pill count badge.
- **message-row** — avatar · (sender + time) · subject · preview, with a left
  accent bar and `bg-active` tint when selected, and an unread dot (with a
  surface-matched halo) when unread. Unread uses `emphasis` weight + `text`;
  read uses normal weight + `text-soft`.
- **card / compose** — `bg-panel`, `lg` radius, `shadow-lg`, float above the app.

Interactive elements show a keyboard-only focus ring (`:focus-visible`), never a
mouse-click outline. All transitions use a shared `cubic-bezier(.2,.8,.2,1)`
easing and respect `prefers-reduced-motion`.

## Do's and Don'ts

**Do**
- Reference tokens (`{colors.primary}`, `{spacing.s4}`) so light and dark both
  resolve and the 4px rhythm holds.
- Keep teal scarce — reserve it for actions and "selected / unread / primary."
- Set all timestamps, addresses, counts, and status text in the mono family with
  `tabular-nums`.
- Separate panels with hairline borders; reserve shadows for floating surfaces.
- Signal unread with weight **and** color, not the dot alone.

**Don't**
- Hardcode a theme's literal hex in a component — it will break the other theme.
- Introduce a second accent hue or a purple/blue gradient; this system is
  mono-accent teal.
- Invent intermediate grays between the three text levels or the surface steps.
- Put body copy in the mono family, or metadata in the sans family.
- Use color as the *only* differentiator for state (pair it with weight, an
  icon, or the accent bar) — and never rely on a focus style that only shows on
  mouse click.
