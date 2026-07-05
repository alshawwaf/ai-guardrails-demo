export function initSettings() {
    // Two-pane settings: a Providers sidebar swaps the detail pane in place.
    // All panes stay in the DOM (only the active one is shown) so the single
    // form still submits every provider's fields on Save.
    const items = document.querySelectorAll(".sp-item");
    const panes = document.querySelectorAll(".sp-pane");
    if (!items.length) return;

    const select = (id) => {
        items.forEach((it) => it.classList.toggle("active", it.dataset.pane === id));
        panes.forEach((p) => p.classList.toggle("active", p.dataset.pane === id));
    };

    items.forEach((it) => it.addEventListener("click", () => select(it.dataset.pane)));

    // Honor a pane pre-marked active in the markup, else the first provider.
    const initial = document.querySelector(".sp-item.active") || items[0];
    select(initial.dataset.pane);
}
