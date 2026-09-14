import { For, Show, type Component } from "solid-js";
import { VIEWS, VIEW_GROUPS, type ViewDef, type ViewId } from "../../app/views";
import { StatusDot, type Tone } from "../ui/primitives";

function capabilityTone(available: boolean, active: boolean): Tone {
  if (!available) return "muted";
  return active ? "info" : "neutral";
}

export const NavRail: Component<{
  active: ViewId;
  onSelect: (id: ViewId) => void;
  capabilityOf: (view: ViewDef) => boolean;
}> = (props) => {
  const move = (event: KeyboardEvent, index: number) => {
    const buttons = Array.from(
      (event.currentTarget as HTMLElement)
        .closest("nav")
        ?.querySelectorAll<HTMLButtonElement>("button[data-view]") ?? [],
    );
    if (buttons.length === 0) return;
    let next = index;
    if (event.key === "ArrowDown" || event.key === "ArrowRight") next = (index + 1) % buttons.length;
    else if (event.key === "ArrowUp" || event.key === "ArrowLeft")
      next = (index - 1 + buttons.length) % buttons.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = buttons.length - 1;
    else return;
    event.preventDefault();
    const target = buttons[next];
    target.focus();
    props.onSelect(target.dataset.view as ViewId);
  };

  return (
    <nav class="nav-rail" aria-label="Workspace sections">
      <For each={VIEW_GROUPS}>
        {(group) => (
          <div class="nav-group">
            <p class="nav-group__label">{group}</p>
            <ul class="nav-group__list">
              <For each={VIEWS.filter((view) => view.group === group)}>
                {(view, index) => (
                  <li>
                    <button
                      type="button"
                      class="nav-item"
                      data-view={view.id}
                      aria-current={props.active === view.id ? "page" : undefined}
                      aria-label={`${view.label} — ${
                        props.capabilityOf(view) ? "capability available" : "capability unavailable"
                      }`}
                      onClick={() => props.onSelect(view.id)}
                      onKeyDown={(event) => move(event, index())}
                      title={view.description}
                    >
                      <StatusDot
                        tone={capabilityTone(props.capabilityOf(view), props.active === view.id)}
                        label={props.capabilityOf(view) ? "capability available" : "capability unavailable"}
                      />
                      <span class="nav-item__label">{view.label}</span>
                      <Show when={!props.capabilityOf(view)}>
                        <span class="nav-item__flag" aria-hidden="true">
                          !
                        </span>
                      </Show>
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </div>
        )}
      </For>
    </nav>
  );
};
