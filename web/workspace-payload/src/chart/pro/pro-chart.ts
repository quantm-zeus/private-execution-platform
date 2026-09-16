// KLineChart Pro lifecycle wrapper.
//
// Pro 0.1.1 has no public `dispose()` and registers a `window` resize listener
// during construction (its Solid root is rendered without keeping the disposal
// fn). The adapter captures that listener so teardown can remove it, and drives
// resize from a `ResizeObserver` on the host so a panel/layout change actually
// repaints the chart.
//
// Pro-specific types stay in this module (and `pro-datafeed.ts`); the component
// only sees `ProChartHandle`.

import { KLineChartPro } from "@klinecharts/pro";
import type { ChartProOptions } from "@klinecharts/pro";
import { PRO_PERIODS, proPeriodForTimeframe, proSymbolFor } from "./pro-datafeed";
import type { ChartSubject } from "../chart-datafeed";

export interface CreateProChartOptions {
  readonly subject: ChartSubject;
  readonly datafeed: ChartProOptions["datafeed"];
  readonly timeframeId?: string;
  /** Inner container test hook. */
  readonly testId?: string;
}

export interface ProChartHandle {
  readonly chart: KLineChartPro;
  readonly disposed: boolean;
  setSubject(subject: ChartSubject): void;
  setTimeframe(timeframeId: string): void;
  resize(): void;
  dispose(): void;
}

function localTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

interface CapturedListener {
  readonly target: EventTarget;
  readonly type: string;
  readonly listener: EventListenerOrEventListenerObject;
  readonly options?: boolean | AddEventListenerOptions;
}

interface ListenerHost {
  addEventListener: (
    type: string,
    listener: EventListenerOrEventListenerObject,
    options?: boolean | AddEventListenerOptions,
  ) => void;
}

/**
 * Capture every `window`/`document` listener Pro registers synchronously while
 * its Solid tree mounts.
 *
 * Pro 0.1.1 discards its Solid disposal function, so the cleanup that would
 * normally remove these listeners never runs. Beyond the single `window`
 * `resize` listener, its period-bar component registers `document`
 * `fullscreenchange` listeners; without capturing them, each workspace
 * teardown/rebuild leaks listeners for the lifetime of the document.
 */
function constructWithListenerCapture(construct: () => KLineChartPro): {
  chart: KLineChartPro;
  listeners: CapturedListener[];
} {
  const listeners: CapturedListener[] = [];
  const windowHost = window as unknown as ListenerHost;
  const documentHost = document as unknown as ListenerHost;
  const originalWindowAdd = windowHost.addEventListener;
  const originalDocumentAdd = documentHost.addEventListener;
  const patch =
    (host: EventTarget, original: ListenerHost["addEventListener"]): ListenerHost["addEventListener"] =>
    (type, listener, options) => {
      listeners.push({ target: host, type, listener, options });
      original.call(host, type, listener, options);
    };
  windowHost.addEventListener = patch(window, originalWindowAdd);
  documentHost.addEventListener = patch(document, originalDocumentAdd);
  try {
    return { chart: construct(), listeners };
  } finally {
    windowHost.addEventListener = originalWindowAdd;
    documentHost.addEventListener = originalDocumentAdd;
  }
}

export function createProChart(host: HTMLElement, options: CreateProChartOptions): ProChartHandle {
  const container = document.createElement("div");
  container.className = "pep-pro-chart";
  if (options.testId) container.setAttribute("data-testid", options.testId);
  host.appendChild(container);

  let chart: KLineChartPro;
  let captured: CapturedListener[] = [];
  try {
    const built = constructWithListenerCapture(
      () =>
        new KLineChartPro({
          container,
          symbol: proSymbolFor(options.subject),
          period: proPeriodForTimeframe(options.timeframeId ?? "1m"),
          // Offer only the periods the local contract can serve; Pro's defaults
          // include windows the canonical `get_chart` cannot express.
          periods: [...PRO_PERIODS],
          theme: "dark",
          timezone: localTimezone(),
          drawingBarVisible: false,
          mainIndicators: ["MA"],
          subIndicators: ["VOL"],
          datafeed: options.datafeed,
        }),
    );
    chart = built.chart;
    captured = built.listeners;
  } catch (error) {
    // A runtime without a usable canvas must not leave a half-mounted widget.
    container.remove();
    throw error;
  }
  const resizeListener = captured.find(
    (entry) =>
      entry.target === window && entry.type === "resize" && typeof entry.listener === "function",
  )?.listener as ((event: Event) => void) | undefined;

  let disposed = false;
  let observer: ResizeObserver | null = null;
  const triggerResize = (): void => {
    resizeListener?.(new Event("resize"));
  };
  if (typeof ResizeObserver !== "undefined") {
    observer = new ResizeObserver(() => triggerResize());
    observer.observe(host);
  }

  return {
    chart,
    get disposed() {
      return disposed;
    },
    setSubject(subject: ChartSubject): void {
      if (disposed) return;
      chart.setSymbol(proSymbolFor(subject));
    },
    setTimeframe(timeframeId: string): void {
      if (disposed) return;
      chart.setPeriod(proPeriodForTimeframe(timeframeId));
    },
    resize(): void {
      if (!disposed) triggerResize();
    },
    dispose(): void {
      if (disposed) return;
      disposed = true;
      observer?.disconnect();
      observer = null;
      // Remove every listener Pro registered on window/document during
      // construction; Pro 0.1.1 never runs its own Solid cleanup.
      for (const { target, type, listener, options } of captured) {
        target.removeEventListener(type, listener, options);
      }
      captured = [];
      // Pro exposes no chart destroy hook; dropping the host detaches the
      // canvas and toolbar. The datafeed owns/cancels its own subscriptions.
      container.remove();
    },
  };
}
