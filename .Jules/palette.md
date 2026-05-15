## 2024-11-20 - Form Accessibility
**Learning:** In React applications, while static IDs work for standard singleton modals, it's safer to use React's `useId()` hook for form accessibility mappings (`htmlFor` & `id`) to prevent potential conflicts if the component is reused.
**Action:** Consider utilizing `useId()` for generic UI components.
