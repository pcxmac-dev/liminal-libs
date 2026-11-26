# The page standard

Every Liminal app's page is held to this: the platform, the login, the integrator and the charts. It is the user's
global interface standard of 2026-11-22 (Monday list item 31): "the right hand menu holds the 'tool' selected on the
left hand menu in the top portion of it's menu. However, if there is amplifying information selected from the main
screen (in between) it shows up as amplifying information underneath the plugin or tools' info in the right hand menu,
this needs to be global for all apps too"; "lets classify the menus too while we are at it, a global interface
standard".

The rules of which tools can be picked at the same time are data, in `src/liminal_libs/ui/static/standard.json`. Every
page reads them through `side.js` (`LiminalSide.standard`), and `liminal_libs.ui.standard` reads the same file in
Python. Both are run on one table of cases (`tests/data/ui_standard_cases.json`), so the two cannot say different
things. `tests/test_ui_standard.py` also holds this text to the file: every app and every group the file has is named
here.

## The five spaces

- **The controller menu** (`controller`): the right-most icon menu, the rail. In an app built on others it picks which
  app fills every other space: the left-hand menu, the main screen, the right-hand menu and the tools overhead.
- **The left-hand menu** (`left`): the app's tools, what its design needs. It sits beside the icon menu and is not the
  icon menu. The platform's are its plugins (interfaces to APIs, hardware, the OS); the charts' are tools of their own
  kind (the drawing tools).
- **The main screen** (`main`): all the useful information, next to the right. In the charts, the chart selected.
- **The tools overhead** (`overhead`): above every menu and screen, as the charts' selectable elements are.
- **The right-hand menu** (`right`): its top element is the tool picked on the left, its symbol and name first, then
  what the tool reports, about itself and the main screen. In the charts the cursor (the arrow tool) says where it is
  over the chart: the price, the time, the bar. Under it, whatever is picked in the main screen is told in full. Any
  other relevant information comes after.

## How many at once

A group of tools says how many of it are picked at once:

- **one**: exactly one. A new pick replaces the old; letting it go goes back to its default.
- **one-or-none**: a new pick replaces the old. A second pick of the same one lets it go, and so does Escape.
- **any**: each pick toggles.

A group may belong to another (`of`): when that one changes, this one goes back to its start (a tab to Main, a pick
away). A group may hold anything but its default only while another group holds certain values (`with`), and one tool
of a group may have such a rule of its own (`only`).

## Each app

### The platform

- `tool` (left, one): the machine, a plugin, an assistant, a database, Connections, Codebase, or the platform's own
  entry (External API, Internal API). The machine at the start.
- `tab` (main, one, of `tool`): Main, External API, Internal API, or a plugin's own tab (World Wide Web, Netstat,
  Filter). Main at the start, and again when the tool changes.
- `pick` (main, one or none, of `tab`): a row of the tab's tables, a place, a router or a feature on its globe, a part
  of Connections, a database. A table row and a globe's item share the one pick.
- The right-hand menu tells the `tool`, then the `pick`.
- The controller: the platform's own icons, and the login's (the platform holds its login as an object).

### The login

- `tool` (left, one): the account (its pairs, the variables asked for), Codebase, a plugin, or the login's own entry.
- `tab` (main, one, of `tool`), and `pick` (main, one or none, of `tab`): a pair, a variable asked for, a row of a
  plugin's tables, a repository. A pick never reveals a value: a pair is told by its name, its kind and when it was
  kept, its value masked as the table masks it.
- The right-hand menu tells the `tool`, then the `pick`.

### The integrator

The integrator's page is the charts' code with no chart (store's `lib.page()`, the fetcher's mode).

- `view` (controller, one): the views on its rail, the Fetcher at the start.
- `pick` (main, one or none, of `view`): a row of the view's middle (a database's table, a plugin's plan, an exchange's
  product, a repository).
- The right-hand menu tells the `view`, then the `pick`.

### The charts

- `view` (controller, one): the rail's views, Stock at the start. Stock, Analysis, Trading, Watchlist and Preferences
  show the chart.
- `drawing` (left, one, only with a chart view): the drawing tools left of the chart, the cursor at the start. A view
  with no chart puts the cursor back.
- `overhead` (overhead, any, only with a chart view): the toggles above the chart, Replay (on Analysis only) and All
  data. The selects overhead (the symbol, the feed, the period, the chart's type, the model, the sessions, the layout)
  each hold one value of their own and are not picked against anything.
- `pick` (main, one or none, of `view`): a row of a three-column view's middle (Plugins, Databases, Exchanges,
  Codebase), a bar of the chart.
- The right-hand menu tells the `drawing` tool (on a chart view: its symbol and name, then what it reports, the cursor's
  price, time and bar), then the `pick`.

## The controller menu in an app built on others

The user, 2026-11-22: "when working with inherited apps like platform, the left most icon screen will allow which 'app'
is present in all the other spaces"; "so charts which inherits platform and integrator will have icons from both those
apps, and you can go directly in to those apps presentations from the right most icon menu (controller menu)".

- The charts hold the platform's and the integrator's icons; the platform holds the login's.
- Each icon goes straight into that app's own presentation, in the same spaces and by the same standard.
- A `controller` list in standard.json names the app first, then the apps it holds. The charts' list names the
  integrator already; its icon on the charts' rail is item 30's work (the charts and the integrator inheriting the
  platform).

## What a page does with a pick

- **Picking.** A click, Enter or Space, or a finger's tap. A pointer's hover never pins a pick: it only shows a tip.
- **Letting go.** Escape, the pick's own "×" (Unpick), or a second click on the same row. The focus goes back to the
  row.
- **A pick belongs to one tool and one view.** Another tool on the left, or another tab, lets it go.
- **Drawn again.** While its tool's view is drawn again (a tab asked every 2 s), the pick is kept by its key and told
  anew. A pick whose row has gone is kept, marked "no longer shown as of" the time it went, until it is let go.
- **A phone** (the page stacked, under 700 px): the pick is scrolled into view, with a "Back to the row" link at its
  head.
- **The words.** A plugin gives the words of its rows, so a page sets them as text, never as markup.

## The shared piece

`src/liminal_libs/ui/static/side.js` (`window.LiminalSide`), loaded after icons.js and before the app's own script:

- `LiminalSide.panel(aside, {app})`: the right-hand menu's two slots, the tool (`.side-tool`) and the pick
  (`.side-pick`). `panel.tool(scope, html)` draws the top again alone, so a status drawn every few seconds never takes
  the pick away; a new scope lets the pick go. `panel.pick(spec)`, `panel.unpick()`, `panel.refresh(find)`.
- `LiminalSide.rows(root, {selector, scope, panel, describe})`: rows picked by a click, Enter, Space or a tap; a
  button, a link, a field or a summary inside a row never picks.
- `LiminalSide.fromRow(tr)`: a row told generically, each cell under its column's heading.
- `LiminalSide.html(spec)`: a pick's markup, for a page drawing its side itself.
- `LiminalSide.standard`: the rules read, with `after` and `problems` as liminal_libs.ui.standard has them.

A pick is told by a spec: `{key, title, sub, icon, facts: [[label, value]], sections: [{title, facts}], note}`. A
plugin's tab page may give one for each row of a table (`tables[i].details`, apps/tabs.py's `detail()`); a row with
none is told by its cells.

## Against an older server or library

- A page whose library has no side.js draws its right-hand menu as before (the page tests for `window.LiminalSide`).
- A tab page whose server gives no row details is told by its cells under their column headings.
