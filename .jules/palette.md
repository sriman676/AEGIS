## 2024-05-16 - [Frontend Accessibility Enhancements]
**Learning:** Found multiple form elements in the React dashboard lacking proper accessibility labels. Form inputs within modals and icon-only buttons lacked `id`/`htmlFor` associations and `aria-label`s respectively, demonstrating a need for strict a11y reviews during component creation.
**Action:** Enforce the addition of `htmlFor` properties to `<label>` tags and matching `id` attributes on inputs, as well as `aria-label` attributes for interactive, icon-only UI components in future PRs.
