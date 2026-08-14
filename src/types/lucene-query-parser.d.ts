declare module 'lucene-query-parser' {
  const lucene: { parse: (query: string) => unknown }
  export default lucene
}
