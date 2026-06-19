---
title: Static Site Pagination
summary: How pagination can work on a static site without a backend or database.
author: Dhico Satria
date: 2026-06-19T05:10:00+07:00
tags:
  - static-site
  - javascript
  - pagination
  - frontend
---

# Static Site Pagination

Pagination does not always require a dynamic backend or a database. A static site can still provide page-like navigation if the data is already available at build time or already present in the HTML.

The important distinction is where the paging happens.

## Current Approach

The Blog catalog currently uses client-side pagination.

At build time, MkDocs produces a normal static HTML page. The page already contains all catalog rows for the current listing. A small JavaScript file then controls which rows are visible.

Implementation details:

- Script: `docs/javascripts/catalog-pagination.js`
- Item selector: `.catalog-row`
- Pagination selector: `.catalog-pagination`
- Items per page: `perPage = 5`
- Buttons:
  - `data-page="prev"`
  - `data-page="next"`
  - `data-page-number`

The script does not fetch data from an API. It only updates the browser DOM.

## How It Works

The rendered HTML contains all rows:

```html
<span class="catalog-row">...</span>
<span class="catalog-row">...</span>
<span class="catalog-row">...</span>
```

The JavaScript groups those rows into pages:

```js
var perPage = 5;
row.hidden = Math.floor(index / perPage) !== current;
```

When the user clicks `next`, `prev`, or a page number, the script changes the active page and rerenders the visible rows.

It also updates the visible summary text:

```text
showing 1-5 of 8
showing 6-8 of 8
```

No database is involved.

## Pagination Models

### Client-side pagination

Client-side pagination keeps all items in one HTML page and uses JavaScript to show or hide rows.

Good for:

- Small to medium catalogs
- Static sites hosted on GitHub Pages
- Simple indexes where SEO for every page number is not important

Tradeoffs:

- All items are shipped in the first HTML response
- Page numbers are UI state, not separate URLs
- Very large catalogs can make the page heavier

### Static multi-page pagination

Static multi-page pagination generates separate files during build:

```text
/notes/page/1/
/notes/page/2/
/notes/page/3/
```

Good for:

- Larger content archives
- Better shareable URLs
- Better search engine indexing per page

Tradeoffs:

- Requires generator support or custom build logic
- More templates and routing rules
- More generated files

### Dynamic pagination

Dynamic pagination asks a backend or API for a page of data:

```text
/api/notes?page=2
```

Good for:

- Very large datasets
- User-specific filtering
- Real-time updates
- Search backed by a database

Tradeoffs:

- Requires backend infrastructure
- Requires API design
- Not available on plain GitHub Pages without external services

## Recommendation for This Site

For Rubberdust, client-side pagination is acceptable for the current Blog catalog because the dataset is small and the site is deployed as a static site.

If the catalog grows significantly, the better next step is static multi-page pagination generated at build time from Markdown front matter or a structured data file.

Dynamic pagination should only be considered if the site moves away from pure static hosting or needs user-specific data.

## Practical Rule

Use this rule of thumb:

- Under 100 list items: client-side pagination is usually fine.
- Hundreds of list items: prefer static multi-page generation.
- User-specific or real-time data: use dynamic pagination.
