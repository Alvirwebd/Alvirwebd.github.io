# Stage previews

Reference renders kept in the repo so they survive sandbox/session resets.

## stage2/ — Stage 2 (surface relief, contact shadows, lighting, floor + vignette)

Merged in PR #6 (`5000a4b`). Rollback points: tags `stage1-geometry-fix` (`be74dfd`)
and `stage2-lighting-pass` (`becfc6f`).

| file | what |
|---|---|
| `before-after.png` | all three viewports, before / after side by side |
| `desktop-1440x900.png` · `phone-390x844.png` · `tablet-1024x768.png` | after |
| `before-*.png` | the same three frames from `be74dfd` (Stage 1, before Stage 2) |

### Fidelity — read this before judging colour

These are **software-rasterised reconstructions**, not screenshots. There is no
headless WebGL in the build environment, so the scene is re-rendered by a small
ray/triangle rasteriser that re-implements the page's light rig, procedural
textures, shadow map, fog, ACES tone curve and the CSS vignette.

* **Trustworthy:** geometry, camera framing, object positions, beacon/chip
  placement, and the *relative* before/after difference.
* **Not trustworthy:** absolute colour, contrast, highlight roll-off, and any
  fine detail below a few pixels. Only a real device tells the truth there.
* Known gaps: contact-shadow opacity is applied per-shadow here (the page uses
  0.26–0.40), the *before* panel's CSS vignette is approximated as a Gaussian
  edge, and the two additive wall halos are synthesised rather than read from a
  canvas (jsdom has no 2D canvas).
* The DOM chrome (identity plate, dock, chips) is not drawn — it is unchanged
  by Stage 2.

### Reproducing

Both frames come from the same renderer, fed by a JSON dump of the live scene
(`scene.traverse` → world-space vertices/normals/UVs + material + light data),
taken from `be74dfd` (before) and `5000a4b` (after) at each viewport.
