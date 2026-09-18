import { For, Show, createEffect, createMemo, createSignal, type Component, type JSX } from "solid-js";
import type {
  TokenAboutPayload,
  TokenAboutProfile,
  TokenAboutStats,
  TradingWindow,
} from "../../contracts/token-intelligence";
import type { RiskAssessment } from "../../contracts/market";
import {
  formatAge,
  formatAmount,
  formatBps,
  formatCount,
  formatSignedPercent,
  formatUsd,
} from "../../core/format";
import { safeHttpUrl } from "../../state/token-intelligence";
import { freshnessView } from "./queries";
import { useWorkstation } from "../../state/workstation";
import { useWorkspace } from "../../state/session";
import { AddressCopy } from "../../components/ui/AddressCopy";
import { MarkTile } from "../../components/ui/MarkTile";
import { Badge, type Tone } from "../../components/ui/primitives";
import { CompactNote, EmptyBlock, ErrorBlock, LoadingBlock } from "../../components/ui/states";

type FlowWindow = "5m" | "1h" | "4h" | "24h";
const FLOW_WINDOWS: readonly FlowWindow[] = ["5m", "1h", "4h", "24h"];

/** A percentage the provider already states in percent units (0-100). */
function formatPercentValue(value: number | null): string {
  return value === null || !Number.isFinite(value) ? "—" : `${value.toFixed(1)}%`;
}

function setFill(element: HTMLElement, percent: number): void {
  // Fill widths go through CSSOM, never an inline style attribute: the payload
  // CSP is style-src 'self' with no unsafe-inline.
  element.style.width = `${Math.max(0, Math.min(100, percent))}%`;
}

const RISK_LEVELS: Readonly<Record<string, { tone: Tone; label: string }>> = {
  clear: { tone: "positive", label: "Clear" },
  hard_risk: { tone: "danger", label: "Hard risk" },
  warning: { tone: "warning", label: "Warning" },
  restricted: { tone: "danger", label: "Restricted" },
};

function riskView(risk: RiskAssessment | null): { tone: Tone; label: string } {
  const level = risk?.level;
  if (typeof level === "string" && RISK_LEVELS[level]) return RISK_LEVELS[level]!;
  // `unknown` is never rendered as safe.
  return { tone: "muted", label: "Unknown" };
}

/**
 * About — the calm token overview. Five stable sections, no feed, no pagination,
 * no transaction rows and no activity state. Availability is per section: a
 * missing provider field renders `—`, and the buy/sell ratio is omitted entirely
 * when the window has no trades.
 */
export const TokenOverviewPanel: Component<{ embedded?: boolean }> = (props) => {
  const station = useWorkstation();
  const ws = useWorkspace();
  const [flowWindow, setFlowWindow] = createSignal<FlowWindow>("1h");

  createEffect(() => {
    if (props.embedded && station.dockTab() !== "about") return;
    if (!station.intelKey() || station.intelDenial()) return;
    if (station.about.state().kind === "idle") station.runIntel("about");
  });

  const about = createMemo<TokenAboutPayload | null>(() => {
    const state = station.about.state();
    if (state.kind === "ready" || state.kind === "stale") return state.value;
    return null;
  });

  // Availability is per section, not per pane: the market snapshot and risk
  // sections are also served by the existing token-detail read, so they still
  // render when the token-overview read is not composed.
  const detailFallback = createMemo(() => station.visibleDetail());
  const fallbackStats = createMemo<TokenAboutStats | null>(() => {
    const detail = detailFallback();
    if (!detail || !detail.stats) return null;
    return {
      priceUsd: detail.stats.priceUsd,
      priceChange24h: detail.stats.priceChange24h,
      marketCapUsd: detail.stats.marketCapUsd,
      fdvUsd: null,
      liquidityUsd: detail.stats.liquidityUsd,
      volume24hUsd: detail.stats.volume24hUsd,
      holders: detail.stats.holders,
      top10HoldersPercent: null,
    };
  });
  const showFallback = createMemo(() => about() === null && fallbackStats() !== null);
  // The pane-wide denial only applies when no section can be served at all.
  const paneDenial = createMemo(() => (showFallback() ? null : station.intelDenial()));

  const staleAgeMs = createMemo<number | null>(() => {
    const view = freshnessView(station.about.state(), ws.nowMs());
    return view !== null && view.stale ? view.ageMs : null;
  });

  const unavailableView = createMemo<JSX.Element | null>(() => {
    if (showFallback()) return null;
    const state = station.about.state();
    return state.kind === "unavailable" ? (
      <div class="pane__scroll">
        <CompactNote label="Token overview" reason={state.reason} capability={state.capability} />
      </div>
    ) : null;
  });
  const errorView = createMemo<JSX.Element | null>(() => {
    if (showFallback()) return null;
    const state = station.about.state();
    return state.kind === "error" ? (
      <div class="pane__scroll">
        <ErrorBlock error={state.error} onRetry={() => station.runIntel("about")} />
      </div>
    ) : null;
  });
  const fallbackView = createMemo<JSX.Element | null>(() => {
    const stats = fallbackStats();
    if (!showFallback() || stats === null) return null;
    const capability = station.intelDenial()?.capability ?? "token_intelligence";
    return (
      <div class="pane__scroll">
        <div class="about">
          <div class="about__col">
            <CompactNote
              label="Token profile"
              reason="The token-profile read is not composed for this deployment, so identity, supply and flow are unavailable."
              capability={capability}
            />
          </div>
          <div class="about__col about__col--b">
            <MarketSection stats={stats} circulatingSupply={null} staleAgeMs={null} />
            <RiskSection risk={detailFallback()?.risk ?? null} warnings={[]} />
          </div>
        </div>
      </div>
    );
  });

  return (
    <section class="pane" data-testid="about-pane">
      <div class="pane__bar">
        <h3 class="pane__title">Token overview</h3>
        <span class="pane__meta">
          {ws.selectedInstrument()?.symbol ?? "—"}
          {ws.selectedInstrument()?.chain ? ` · ${ws.selectedInstrument()!.chain}` : ""}
        </span>
      </div>

      <Show when={paneDenial()}>
        {(denial) => (
          <div class="pane__scroll">
            <CompactNote
              label="Token overview"
              reason={denial().reason}
              capability={denial().capability}
            />
          </div>
        )}
      </Show>

      <Show when={paneDenial() === null}>
        <Show when={station.about.state().kind === "loading" && about() === null && !showFallback()}>
          <div class="pane__scroll">
            <LoadingBlock label="Loading token overview…" />
          </div>
        </Show>
        {unavailableView()}
        {errorView()}
        {fallbackView()}
        <Show when={about()}>
          {(payload) => (
            <div class="pane__scroll">
              <div class="about">
                <div class="about__col">
                  <ProfileSection payload={payload()} />
                  <SupplySection stats={payload().stats} profile={payload().profile} />
                </div>
                <div class="about__col about__col--b">
                  <MarketSection
                    stats={payload().stats}
                    circulatingSupply={payload().profile.circulatingSupply}
                    staleAgeMs={staleAgeMs()}
                  />
                  <FlowSection
                    window={flowWindow()}
                    onWindow={setFlowWindow}
                    trading={payload().trading}
                  />
                  <RiskSection risk={payload().risk} warnings={payload().warnings} />
                </div>
              </div>
            </div>
          )}
        </Show>
      </Show>
    </section>
  );
};

const Section: Component<{
  title: string;
  testId?: string;
  tools?: JSX.Element;
  children: JSX.Element;
}> = (props) => (
  <section class="sect" data-testid={props.testId}>
    <div class="sect__head">
      <h4 class="sect__title">{props.title}</h4>
      <Show when={props.tools}>
        <span class="sect__tools">{props.tools}</span>
      </Show>
    </div>
    <div class="sect__body">{props.children}</div>
  </section>
);

const ProfileSection: Component<{ payload: TokenAboutPayload }> = (props) => {
  const socials = createMemo(() => {
    const links = props.payload.token.socialLinks;
    // Only an absolute http(s) URL renders; anything else is dropped.
    const safe = (value: string | null): string | null => safeHttpUrl(value);
    return [
      { key: "twitter", label: "X", url: safe(links.twitter) },
      { key: "website", label: "Website", url: safe(links.website) },
      { key: "telegram", label: "Telegram", url: safe(links.telegram) },
      { key: "discord", label: "Discord", url: safe(links.discord) },
    ].filter((entry) => entry.url !== null);
  });
  const missing = createMemo(() => 4 - socials().length);
  const graduation = createMemo(() => props.payload.profile.graduationPercent);
  const created = createMemo(() => props.payload.profile.createdAtMs);

  return (
    <Section title="Token profile" testId="about-profile">
      <div class="tp">
        <MarkTile
          symbol={props.payload.token.symbol ?? props.payload.token.name ?? "?"}
          src={props.payload.token.imageUrl}
        />
        <span class="tp__id">
          <span class="tp__name">{props.payload.token.name ?? "—"}</span>
          <span class="tp__sym">
            {props.payload.token.symbol ?? "—"} · {props.payload.token.chain}
          </span>
        </span>
      </div>
      <div class="grad">
        <span class="grad__track">
          <Show when={graduation() !== null && graduation()! > 0}>
            <span
              class="grad__fill"
              ref={(element) => setFill(element, graduation() ?? 0)}
            />
          </Show>
        </span>
        <span class="grad__val">
          {graduation() === null || graduation()! <= 0
            ? "Graduation —"
            : `${Math.round(graduation()!)}% graduated`}
        </span>
      </div>
      <dl class="tp__rows">
        <div class="tp__row">
          <dt>Contract</dt>
          <dd>
            <AddressCopy address={props.payload.token.address} chain={props.payload.token.chain} />
          </dd>
        </div>
        <Show when={props.payload.profile.launchpad}>
          {(launchpad) => (
            <div class="tp__row">
              <dt>Launchpad</dt>
              <dd>{launchpad()}</dd>
            </div>
          )}
        </Show>
        <Show when={created()}>
          {(createdAt) => (
            <div class="tp__row">
              <dt>Created</dt>
              <dd>{formatAge(Math.max(0, Date.now() - createdAt()))} ago</dd>
            </div>
          )}
        </Show>
      </dl>
      <Show
        when={socials().length > 0}
        fallback={<p class="prov">No social links are published for this token.</p>}
      >
        <div class="tp__links">
          <For each={socials()}>
            {(link) => (
              <a
                class="extlink"
                href={link.url!}
                target="_blank"
                rel="noopener noreferrer"
                title={`${link.label} — opens in a new tab`}
              >
                {link.label}
                <svg
                  viewBox="0 0 16 16"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.5"
                  aria-hidden="true"
                >
                  <path d="M6 3.5h6.5V10M12.5 3.5 5 11" />
                </svg>
              </a>
            )}
          </For>
        </div>
        <Show when={missing() > 0}>
          <p class="prov">{missing()} of 4 social links are not published.</p>
        </Show>
      </Show>
    </Section>
  );
};

function derivedMarketCap(stats: TokenAboutStats, circulating: number | null): number | null {
  if (stats.marketCapUsd !== null) return stats.marketCapUsd;
  if (stats.priceUsd !== null && circulating !== null) return stats.priceUsd * circulating;
  return null;
}

const MarketSection: Component<{
  stats: TokenAboutStats;
  circulatingSupply: number | null;
  staleAgeMs: number | null;
}> = (props) => {
  const cells = createMemo<readonly [string, string][]>(() => [
    ["Price", props.stats.priceUsd === null ? "—" : formatUsd(props.stats.priceUsd, 6)],
    [
      "24h change",
      props.stats.priceChange24h === null ? "—" : formatSignedPercent(props.stats.priceChange24h),
    ],
    ["Market cap", formatUsd(derivedMarketCap(props.stats, props.circulatingSupply))],
    ["Liquidity", formatUsd(props.stats.liquidityUsd)],
    ["24h volume", formatUsd(props.stats.volume24hUsd)],
  ]);
  return (
    <Section
      title="Market snapshot"
      testId="about-market"
      tools={
        <Show when={props.staleAgeMs !== null}>
          <span class="stale">Stale · {formatAge(props.staleAgeMs ?? 0)}</span>
        </Show>
      }
    >
      <StatGrid cells={cells()} />
    </Section>
  );
};

const SupplySection: Component<{ stats: TokenAboutStats; profile: TokenAboutProfile }> = (props) => {
  const cells = createMemo<readonly [string, string][]>(() => [
    ["Holders", formatCount(props.stats.holders)],
    ["Top 10 holders", formatPercentValue(props.stats.top10HoldersPercent)],
    ["Circulating", formatAmount(props.profile.circulatingSupply, 0)],
    ["Total supply", formatAmount(props.profile.totalSupply, 0)],
  ]);
  return (
    <Section title="Ownership / supply" testId="about-supply">
      <StatGrid cells={cells()} />
    </Section>
  );
};

const FlowSection: Component<{
  window: FlowWindow;
  onWindow: (window: FlowWindow) => void;
  trading: TokenAboutPayload["trading"];
}> = (props) => {
  const window = createMemo<TradingWindow | null>(() => props.trading[props.window]);
  const total = createMemo(() => {
    const value = window();
    if (!value || value.buyCount === null || value.sellCount === null) return null;
    return value.buyCount + value.sellCount;
  });
  const buyPercent = createMemo<number | null>(() => {
    const value = window();
    const count = total();
    if (!value || count === null || count <= 0 || value.buyCount === null) return null;
    return Math.round((value.buyCount / count) * 100);
  });
  const cells = createMemo<readonly [string, string][]>(() => {
    const value = window();
    if (!value) return [];
    return [
      ["Buys", formatCount(value.buyCount)],
      ["Sells", formatCount(value.sellCount)],
      ["Buy volume", formatUsd(value.buyVolumeUsd)],
      ["Sell volume", formatUsd(value.sellVolumeUsd)],
      ["Unique buyers", formatCount(value.uniqueBuyers)],
      ["Unique sellers", formatCount(value.uniqueSellers)],
    ];
  });
  return (
    <Section
      title="Buy / sell flow"
      testId="about-flow"
      tools={
        <div class="seg" role="group" aria-label="Flow window">
          <For each={FLOW_WINDOWS}>
            {(id) => (
              <button
                type="button"
                class="seg__btn"
                data-testid={`flow-window-${id}`}
                aria-pressed={props.window === id}
                title={`${id} window`}
                onClick={() => props.onWindow(id)}
              >
                {id}
              </button>
            )}
          </For>
        </div>
      }
    >
      <Show
        when={window()}
        fallback={<p class="prov">Buy and sell flow is not available for this token.</p>}
      >
        <StatGrid cells={cells()} />
        <div class="ratio">
          <Show
            when={buyPercent() !== null}
            fallback={
              // No denominator ⇒ no bar at all. Unknown counts are a different
              // fact from a zero-trade window and say so differently.
              <span class="ratio__legend">
                {total() === null
                  ? "Buy / sell counts are unavailable for this window"
                  : "No trades in this window"}
              </span>
            }
          >
            <span class="ratio__track">
              <span
                class="ratio__buy"
                ref={(element) => setFill(element, buyPercent() ?? 0)}
              />
              <span
                class="ratio__sell"
                ref={(element) => setFill(element, 100 - (buyPercent() ?? 0))}
              />
            </span>
            <span class="ratio__legend">
              {buyPercent()}% buy · {100 - (buyPercent() ?? 0)}% sell
            </span>
          </Show>
        </div>
      </Show>
    </Section>
  );
};

const RiskSection: Component<{ risk: RiskAssessment | null; warnings: readonly string[] }> = (props) => {
  const view = createMemo(() => riskView(props.risk));
  const buying = (): string => {
    const disabled = props.risk?.disableBuying;
    if (disabled === true) return "Disabled";
    if (disabled === false) return "Enabled";
    return "—";
  };
  const selling = (): string => {
    const disabled = props.risk?.disableSelling;
    if (disabled === true) return "Disabled";
    if (disabled === false) return "Enabled";
    if (props.risk?.sellRestricted === true) return "Restricted";
    return "—";
  };
  const cells = createMemo<readonly [string, string][]>(() => [
    ["Buying", buying()],
    ["Selling", selling()],
    ["Buy tax", formatBps(props.risk?.buyTaxBps ?? null)],
    ["Sell tax", formatBps(props.risk?.sellTaxBps ?? null)],
  ]);
  return (
    <Section
      title="Risk / warnings"
      testId="about-risk"
      tools={<Badge tone={view().tone}>{view().label}</Badge>}
    >
      <StatGrid cells={cells()} />
      <Show
        when={props.warnings.length > 0}
        fallback={<p class="prov">No provider warnings reported.</p>}
      >
        <ul class="warnlist">
          <For each={props.warnings}>{(warning) => <li>{warning}</li>}</For>
        </ul>
      </Show>
      <p class="prov">
        Buy and sell tax are reported only by a verified provider. When none is composed both stay
        unknown rather than 0.
      </p>
    </Section>
  );
};

const StatGrid: Component<{ cells: readonly (readonly [string, string])[] }> = (props) => (
  <dl class="statgrid">
    <For each={props.cells}>
      {([label, value]) => (
        <div class="statgrid__cell">
          <dt>{label}</dt>
          <dd data-unknown={value === "—" ? "true" : undefined}>{value}</dd>
        </div>
      )}
    </For>
  </dl>
);

export default TokenOverviewPanel;
