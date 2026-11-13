// lzma 包没有官方类型,这里给最小声明
declare module 'lzma' {
  interface LzmaStatic {
    compress(
      input: string | Uint8Array,
      mode: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9,
      onFinish?: (result: Uint8Array, error: Error | null) => void
    ): Uint8Array;
    decompress(
      input: Uint8Array,
      onFinish?: (result: string | Uint8Array | null, error: Error | null) => void
    ): string | Uint8Array | null;
  }
  const LZMA: LzmaStatic;
  export default LZMA;
}
