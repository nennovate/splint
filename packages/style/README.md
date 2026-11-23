# Splint's look

Every page a person sees uses these files: the controls, an agent's request, `splint page`, the page behind a one-use link and a host's own notices. Each server embeds them, so nothing loads from anywhere else.

| File | What it is |
|---|---|
| `tokens.css` | Colors in light and dark, type, corners and shadows, and the mark's faces. Every page loads it first. |
| `splint.css` | The controls' components, built on the tokens. |
| `splint-mark.svg`, `splint-mark-dark.svg` | The mark in fixed colors, for light and dark grounds, where a page can't read the tokens. |

The mark is two upright blocks side by side, one a step above the other, with one teal band wrapped around both. On a page that loads `tokens.css`, draw it inline with the `mark` class and its faces' classes, so it follows the theme. Keep clear space around it of at least the band's width, and don't recolor it, outline it or set it on a photo.

## The Splint name and mark

Splint's licences cover its code. They give no rights to the Splint name or mark, which belong to Nennovate, LLC. You can use them to refer to Splint, as in "works with Splint". Don't use them in a way that suggests your project, host or service is Splint, or is run or endorsed by Nennovate.
