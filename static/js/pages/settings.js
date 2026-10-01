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

    // A field that fails browser validation in a hidden pane cannot be focused,
    // so the browser would cancel Save without any message. Show the pane of
    // the first invalid field ("invalid" fires before the browser reports it).
    const form = document.querySelector(".settings-form");
    let shownForThisSubmit = false;
    if (form) {
        form.addEventListener("invalid", (event) => {
            if (shownForThisSubmit) return;
            const pane = event.target && event.target.closest ? event.target.closest(".sp-pane") : null;
            if (!pane || !pane.dataset.pane) return;
            shownForThisSubmit = true;
            select(pane.dataset.pane);
            setTimeout(() => { shownForThisSubmit = false; }, 0);
        }, true); // "invalid" does not bubble: listen in the capture phase
    }

    // Honor a pane pre-marked active in the markup, else the first provider.
    const initial = document.querySelector(".sp-item.active") || items[0];
    select(initial.dataset.pane);
}
