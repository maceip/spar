# Astryx Design System Mastery

Use this playbook whenever the project uses `@astryxdesign/core` (Meta's open-source React 19 + StyleX design system, `https://astryx.atmeta.com/`) or the user asks to build, theme, customize, migrate, or audit an Astryx UI.

## 1. Detect and Inspect First

Check `package.json` and the lockfile for `@astryxdesign/core`, `@astryxdesign/cli`, `@stylexjs/stylex`, `@astryxdesign/theme-*`, and integration packages (`@astryxdesign/charts`, `@astryxdesign/richtext`, `@astryxdesign/lab`).

Prefer the project's installed CLI invocation (`bunx @astryxdesign/cli` or `npx @astryxdesign/cli` or the project's `astryx` script). Always inspect live metadata before writing code; never guess prop names, import paths, or token names.

Key CLI queries (use `--json` for structured data or `--dense` for token-efficient text):
- `astryx build "<surface idea>" --json`: returns the closest page template, fallback templates, blocks, and components.
- `astryx template --list --type page --json`: lists every page template (`ai-chat`, `ai-chat-landing`, `dashboard`, `login`, `blank`, `canvas-editor`, `library`, `centered-hero`, `payment-form`, `checkout-wizard`, `classic-gallery`, `side-gallery`, `shell-side-nav`, `shell-top-nav`, `table-tree`, `form-two-column`, `form-wizard-vertical`, `work-item-detail`, `theme-showcase`, etc.).
- `astryx template <name> <path>`: scaffolds a page template into `<path>`; `astryx template <BlockName>` prints a block snippet.
- `astryx component --list --json` and `astryx component <Name> --dense`: lists all 150+ components and prints exact props, subpath imports, and theme overrides.
- `astryx hook --json` and `astryx hook <Name> --dense`: lists accessibility, focus, interaction, layout, motion, streaming, and table hooks.
- `astryx search <query> --json`: ranked lookup across components, hooks, docs, templates, and themes.
- `astryx docs <topic> --dense`: reads official docs (`principles`, `getting-started`, `styling-overview`, `styling`, `layout`, `tokens`, `theme`, `use-a-theme`, `author-a-theme`, `is-my-code-good`, `migration`, `icons`, `motion`).
- `astryx doctor`: diagnoses Astryx project health, cascade layers, and theme descriptors.
- Remote MCP endpoint: `https://astryx.atmeta.com/mcp` exposes the same live catalog to MCP-capable agents.
- Local Impeccable Web API: when the local service is running (`http://127.0.0.1:4820`), query `/api/astryx/search`, `/api/astryx/components/:name`, `/api/astryx/templates/:name`, `/api/astryx/themes`, `/api/astryx/docs/:topic`, `POST /api/astryx/build-kit`, and `POST /api/audit/astryx`.

## 2. The 8 On-System Rules

Every Astryx surface must obey these eight rules:
1. **Use components over raw primitives.** Import each component from its own subpath (`@astryxdesign/core/Button`, `@astryxdesign/core/VStack`) as printed by `astryx component <Name>`. Avoid barrel imports when subpath entries exist.
2. **Frame-first layout.** Settle the shell (`AppShell`, `SideNav`, `TopNav`) and region budgets before content exists. Never lay out a page from scratch: start from `astryx build "<idea>"` and scaffold the closest page template. Keep the template's page frame, gap, and padding values while replacing its data, copy, and sections.
3. **Dense data uses rows, not Cards.** Use `Table` or `List`/item rows for dense or scannable collections. Reserve `Card`, `ClickableCard`, and `SelectableCard` for widgets, galleries, and settings groups. Never wrap list items in `Card`.
4. **No raw `<div>` layout or inline `style={{}}`.** Use `VStack`, `HStack`, `Stack`, `Grid`, and component props. For custom layout or overrides, use `xstyle` (StyleX), Tailwind bridge utilities, or semantic CSS tokens.
5. **Semantic tokens only.** Never hardcode hex, rgb, hsl, or arbitrary pixel spacing. Use semantic tokens (`--color-*`, `--spacing-*`, `--radius-*`, `--shadow-*`, `--duration-*`, `--ease-*`, `--font-size-*`) and `light-dark()` pairs so dark mode and theme switching work automatically.
6. **CSS custom properties for color.** Every color token resolves through CSS variables (`--color-background-surface`, `--color-text-primary`, `--color-accent`, etc.) or Tailwind semantic bridge classes (`bg-surface`, `text-primary`). Data visualization uses `dataVars` from `@astryxdesign/core/theme/dataTokens.stylex`.
7. **Controlled form inputs.** Manage form state explicitly with controlled props, validation states, and accessible error messaging.
8. **Navigation through `useLinkComponent()`.** Never hardcode raw `<a>` elements for app routing; integrate the router via `useLinkComponent()` and Astryx link/navigation components.

Additional anti-patterns to reject:
- Decorative `Badge` for status indicators: use `StatusDot` or `Token` for status.
- Using `Button variant="primary"` for active state on tabs, segmented controls, or toolbar switchers: reserve `variant="primary"` for the single primary action per viewport; use neutral raised selection (`Tabs`, segmented tracks) for active toggles.
- Direct external icon imports when a semantic Astryx icon name exists (`astryx docs icons`).
- Inventing component props without reading `astryx component <Name> --dense`.
- Upgrading only one `@astryxdesign/*` package: always upgrade all `@astryxdesign/*` packages together to the same release, then run `astryx upgrade --from <oldVersion> --apply`.

## 3. Styling and Cascade Layer Architecture

Astryx requires React 19+ (`react` and `react-dom` >= 19.0.0) and `@stylexjs/stylex`. Component styles are prebuilt and placed in CSS cascade layers (`reset`, `astryx-base`, `astryx-theme`). Pick one of three paths (they can coexist):

### Plain CSS (zero build plugins)
```css
@import "@astryxdesign/core/reset.css";
@import "@astryxdesign/core/astryx.css";
@import "@astryxdesign/theme-neutral/theme.css";
```
Add optional package stylesheets after `astryx.css` and before `theme.css`: `@astryxdesign/richtext/richtext.css`, `@astryxdesign/lab/lab.css`, `@astryxdesign/charts/charts.css`.

### Tailwind v4 (explicit `@layer` order required)
```css
@layer reset, theme, base, astryx-base, astryx-theme, components, utilities;

@import "tailwindcss/theme.css" layer(theme);
@import "tailwindcss/preflight.css" layer(base);
@import "@astryxdesign/core/reset.css";
@import "@astryxdesign/core/astryx.css";
@import "@astryxdesign/theme-neutral/theme.css";
@import "@astryxdesign/core/tailwind-theme.css";
@import "tailwindcss/utilities.css" layer(utilities);
```
Without the explicit `@layer` declaration, `astryx-base` outranks Tailwind utilities and `className` overrides fail. Unlayered global resets (such as `*{padding:0}`) override `astryx-base` regardless of specificity; always place legacy CSS in an explicit layer before `astryx-base`.

### StyleX for App Code and Swizzled Components
Only required when authoring `stylex.create()` in app code or using `astryx swizzle`. Keep prebuilt `astryx.css` and point the StyleX compiler (`@stylexjs/webpack-plugin`, `@stylexjs/rollup-plugin`, `@stylexjs/babel-plugin`, or `@stylexswc/nextjs-plugin`) strictly at app source, never `node_modules/@astryxdesign`.

## 4. Theming, Tokens, and Dark Mode

Wrap the app root once in `<Theme>` from `@astryxdesign/core/theme`:
```tsx
import {Theme} from '@astryxdesign/core/theme';
import {themes, defaultThemeSlug} from './astryx-themes';

<Theme theme={themes[defaultThemeSlug]}><App /></Theme>
```

Seven bundled themes are available via `astryx theme list`:
- `neutral` (maintained default): restrained warm grays, Figtree type.
- `butter`: warm creamy yellows, blue accents, Sarina + Outfit.
- `chocolate`: rich brown palette, Fraunces + Albert Sans, Lucide icons.
- `gothic`: dark-only noir ink, deep blue-grays, display serif.
- `matcha`: earthy greens, DM Sans + Playwrite US Trad.
- `stone`: warm sandstone and slate, Montserrat + Figtree.
- `y2k`: hot pinks, lime greens, Poppins retro pop.

Theme workflow:
1. Add a package theme: `bun add @astryxdesign/theme-<slug>` then `astryx theme add <slug>`. Switch default with `astryx theme use <slug>`.
2. Customize without forking: `defineTheme({ extends: importedTheme, tokens: { '--color-accent': ['#0064E0', '#2694FE'] }, components: { ... }, motion: { tempo: 1, character: 'standard' } })`. Always pass `[light, dark]` tuples for color tokens.
3. Palette generation: `astryx theme palette generate palette.config.json --out palette.generated.ts`, then map semantic tokens to stable stops (`palette.neutral.light[100]`, `palette.neutral.dark[15]`).
4. Visual theme editing: use `astryx experimental theme editor new <name> --like neutral`, iterate with `editor set` / `editor how "<intent>"`, and inspect with `astryx experimental theme editor show <name> --png`. A theme change is not done until you inspect the rendered PNGs.
5. Fork only when requested: `astryx theme eject <slug>` creates an independent local copy that no longer receives upstream theme updates. Build local themes with `astryx theme build <themeFile>`.

Token system summary:
- **Color**: 291 semantic tokens using `light-dark()` across a 4-tier surface hierarchy (`--color-background-body` -> `--color-background-surface` -> `--color-background-card` -> `--color-background-popover`). Import `colorVars`, `spacingVars`, `sizeVars`, `radiusVars` from `@astryxdesign/core/theme/tokens.stylex`; import `dataVars` (56 tokens, 10 series) from `@astryxdesign/core/theme/dataTokens.stylex`; use `resolveThemeToken()` or `useTheme().token()` for Canvas/imperative APIs.
- **Spacing**: 4px (`0.25rem`) rhythmic scale (`--spacing-0` through `--spacing-12`); pass step integers to props (`gap={2}`, `padding={4}`).
- **Size and focus**: fixed control heights (`--size-element-sm` 28px, `md` 32px, `lg` 36px) paired with density controls; 1px `--border-width`; focus ring `--focus-outline-width: 2px` with `3px` offset in `var(--color-accent)`.
- **Radius and concentric shape**: `--radius-none`, `--radius-inner` (8px), `--radius-element` (12px), `--radius-container` (16px), `--radius-chat` (28px), `--radius-page` (32px), `--radius-full` (9999px). Enforce concentric nesting: `max(0px, calc(outerRadius - padding))`.
- **Elevation**: flat (`none`) is default for all surfaces except `ChatComposer`; use `--shadow-low`, `--shadow-med`, `--shadow-high` for floating layers and `--shadow-inset-*` (`hover`, `selected`, `success`, `warning`, `error`) for state rings.
- **Motion**: `fast` / `medium` / `slow` durations scaled by `tempo` (0.75 to 1.5), and `crisp` / `standard` / `expressive` easing `character`, respecting the 200ms reduced-motion cap.
- **Typography**: geometric scale `round(14 * 1.2^step)` anchored on 14px (`0.875rem`) `--font-size-base`, with semantic roles (`Display 1..3`, `H1..H6`, `Body`, `Label`, `Code`, `Supporting`).

## 5. Customization Ladder

Climb only as high as the requirement demands:
1. **Component props**: variants, sizes, density, semantic slots.
2. **Theme tokens**: `defineTheme` token overrides and `components` slot styles.
3. **Targeted overrides**: `className` (plain CSS or Tailwind bridge) or typed `xstyle` (`stylex.create()`).
4. **Swizzle (last resort)**: `astryx swizzle <Component>` ejects full component source into a dedicated folder (default `components/astryx`) with an `astryx-swizzle.json` marker so it compiles into `astryx-base`. Warn the user that swizzled components leave the upstream upgrade path.

## 6. Evidence-Backed Astryx Code Review

When auditing or reviewing Astryx code (from `astryx docs is-my-code-good`):
1. Distinguish **Source check** (raw HTML, inline styles, hardcoded colors/spacing, direct icons, barrel/unsupported imports, missing `@layer`) from **Full product review** (route context, sibling surface parity, rendered narrow/wide viewports, light/dark modes, interactive states, keyboard/screen-reader accessibility, type-check/tests).
2. Inspect at least two sibling surfaces and record app-owned wrappers and documented intentional conventions before flagging deviations.
3. Mark every rubric category `good`, `needs work`, or `not inspected`. Never mark a category `good` without citing file/line or rendered state evidence.
4. Combine this rubric with [craft-floor.md](craft-floor.md) and [audit.md](audit.md): Astryx provides system integrity, while Impeccable ensures hierarchy, contrast, copy clarity, and real visual craft.
