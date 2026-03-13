declare module 'streamsaver' {
  interface CreateWriteStreamOptions {
    size?: number;
    writableStrategy?: unknown;
    readableStrategy?: unknown;
  }
  const streamsaver: {
    createWriteStream(
      filename: string,
      options?: CreateWriteStreamOptions
    ): WritableStream<Uint8Array>;
  };
  export default streamsaver;
}
