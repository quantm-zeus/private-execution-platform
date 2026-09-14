import { type Component } from "solid-js";
import ChartPanel from "../../chart/ChartPanel";
import { Panel } from "../../components/ui/primitives";

export interface TerminalPanelProps {
  readonly entityKey?: string;
}

/** Local realtime terminal: Canvas chart + depth, rendered from worker frames. */
export const TerminalPanel: Component<TerminalPanelProps> = (props) => (
  <Panel
    title="Local chart & depth"
    subtitle="Encrypted, sequenced frames are decrypted in the worker and rendered locally on Canvas"
  >
    <ChartPanel entityKey={props.entityKey} />
  </Panel>
);

export default TerminalPanel;
