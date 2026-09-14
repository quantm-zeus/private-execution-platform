/**
 * Fixed-capacity numeric ring buffers backed by TypedArrays. Bounded by
 * construction so a slow consumer or adversarial feed can never grow memory.
 */

export class NumericRingBuffer {
  private readonly data: Float64Array;
  private head = 0;
  private count = 0;

  constructor(readonly capacity: number) {
    if (!Number.isSafeInteger(capacity) || capacity <= 0) {
      throw new Error("ring buffer capacity must be a positive integer");
    }
    this.data = new Float64Array(capacity);
  }

  get length(): number {
    return this.count;
  }

  push(value: number): void {
    const index = (this.head + this.count) % this.capacity;
    this.data[index] = value;
    if (this.count < this.capacity) {
      this.count += 1;
    } else {
      this.head = (this.head + 1) % this.capacity;
    }
  }

  /** Index 0 is the oldest retained value. */
  get(index: number): number | undefined {
    if (index < 0 || index >= this.count) return undefined;
    return this.data[(this.head + index) % this.capacity];
  }

  last(): number | undefined {
    return this.get(this.count - 1);
  }

  first(): number | undefined {
    return this.get(0);
  }

  toArray(): number[] {
    const out = new Array<number>(this.count);
    for (let i = 0; i < this.count; i++) out[i] = this.data[(this.head + i) % this.capacity]!;
    return out;
  }

  clear(): void {
    this.head = 0;
    this.count = 0;
  }
}

export interface CandleLike {
  readonly timeMs: number;
  readonly open: number;
  readonly high: number;
  readonly low: number;
  readonly close: number;
  readonly volume: number;
}

const FIELDS = 6;

/** Ring buffer of OHLCV candles stored column-major in one Float64Array. */
export class CandleRingBuffer {
  private readonly data: Float64Array;
  private head = 0;
  private count = 0;

  constructor(readonly capacity: number) {
    if (!Number.isSafeInteger(capacity) || capacity <= 0) {
      throw new Error("candle ring capacity must be a positive integer");
    }
    this.data = new Float64Array(capacity * FIELDS);
  }

  get length(): number {
    return this.count;
  }

  push(candle: CandleLike): void {
    const slot = this.count < this.capacity ? (this.head + this.count) % this.capacity : this.head;
    const base = slot * FIELDS;
    this.data[base] = candle.timeMs;
    this.data[base + 1] = candle.open;
    this.data[base + 2] = candle.high;
    this.data[base + 3] = candle.low;
    this.data[base + 4] = candle.close;
    this.data[base + 5] = candle.volume;
    if (this.count < this.capacity) {
      this.count += 1;
    } else {
      this.head = (this.head + 1) % this.capacity;
    }
  }

  at(index: number): CandleLike | undefined {
    if (index < 0 || index >= this.count) return undefined;
    const base = ((this.head + index) % this.capacity) * FIELDS;
    return {
      timeMs: this.data[base]!,
      open: this.data[base + 1]!,
      high: this.data[base + 2]!,
      low: this.data[base + 3]!,
      close: this.data[base + 4]!,
      volume: this.data[base + 5]!,
    };
  }

  last(): CandleLike | undefined {
    return this.at(this.count - 1);
  }

  /** Overwrite the newest candle in place (streaming bar update). */
  replaceLast(candle: CandleLike): boolean {
    if (this.count === 0) return false;
    const slot = (this.head + this.count - 1) % this.capacity;
    const base = slot * FIELDS;
    this.data[base] = candle.timeMs;
    this.data[base + 1] = candle.open;
    this.data[base + 2] = candle.high;
    this.data[base + 3] = candle.low;
    this.data[base + 4] = candle.close;
    this.data[base + 5] = candle.volume;
    return true;
  }

  first(): CandleLike | undefined {
    return this.at(0);
  }

  toArray(): CandleLike[] {
    const out = new Array<CandleLike>(this.count);
    for (let i = 0; i < this.count; i++) out[i] = this.at(i)!;
    return out;
  }

  clear(): void {
    this.head = 0;
    this.count = 0;
  }
}
