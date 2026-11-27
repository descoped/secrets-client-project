// The living figures of the landing page: SVG drawn on the server and moved by CSS alone (globals.css, "Figures").
// A figure steps through four states, the classes s0 to s3, four seconds each, shown one at a time; what does not
// change is drawn once. With reduced motion a figure shows one still frame, its second state (s1). The facts are the
// documentation's: api.md (guarded memory), security.md (the canary tests) and the providers' pages (TLS).

const CHAR = 7.8

/** A value drawn as a small card: plain, open (lit), leaked (danger) or wiped (dashed) */
function Chip({
  x,
  y,
  text,
  kind = 'plain',
}: {
  x: number
  y: number
  text: string
  kind?: 'plain' | 'open' | 'leak' | 'wiped'
}): React.ReactElement {
  const box = { plain: 'fig-bar', open: 'fig-bar-on', leak: 'fig-leak', wiped: 'fig-bar fig-bar-gone' }[kind]
  return (
    <g>
      <rect className={box} x={x} y={y} width={text.length * CHAR + 16} height={24} rx={4} />
      <text className={kind === 'wiped' ? 'fig-gone' : kind === 'leak' ? 'fig-missing' : undefined} x={x + 8} y={y + 16}>
        {text}
      </text>
    </g>
  )
}

/** A step of a pipeline: a box with two lines, lit when it holds a secret safely, red when it leaks */
function Stage({
  x,
  y,
  w = 120,
  title,
  note,
  kind = 'plain',
}: {
  x: number
  y: number
  w?: number
  title: string
  note: string
  kind?: 'plain' | 'open' | 'leak'
}): React.ReactElement {
  const box = { plain: 'fig-card', open: 'fig-bar-on', leak: 'fig-leak' }[kind]
  return (
    <g>
      <rect className={box} x={x} y={y} width={w} height={54} rx={8} />
      <text className="fig-title" x={x + w / 2} y={y + 23} textAnchor="middle">
        {title}
      </text>
      <text className={kind === 'leak' ? 'fig-small fig-missing' : 'fig-small'} x={x + w / 2} y={y + 41} textAnchor="middle">
        {note}
      </text>
    </g>
  )
}

/** An arrow from one stage to the next, its dashes flowing */
function Flow({ x1, x2, y }: { x1: number; x2: number; y: number }): React.ReactElement {
  return (
    <g>
      <line className="fig-link" x1={x1} y1={y} x2={x2 - 6} y2={y} />
      <path className="fig-arrow" d={`M${x2 - 10} ${y - 5}l6 5-6 5`} />
    </g>
  )
}

/**
 * A String and a Secret, side by side, through four moments: read, use, done, heap dump. The String is copied by the
 * garbage collector and cannot be wiped, so the dump finds three copies; the Secret is off the heap, opened for one
 * callback whose copy is zeroed, and wiped on close, so the dump finds nothing.
 */
export function HeapDumpFigure(): React.ReactElement {
  const captions = [
    '1  Read: the String lands on the heap, the Secret in guarded memory',
    '2  Use: the GC copies the String; the Secret opens for one callback',
    '3  Done: the String stays until collected; the Secret is wiped',
    '4  Heap dump: three copies of the String, nothing of the Secret',
  ]
  return (
    <svg className="fig" viewBox="0 0 640 300" role="img" aria-labelledby="fig-heap-title fig-heap-desc">
      <title id="fig-heap-title">A String and a Secret in a heap dump</title>
      <desc id="fig-heap-desc">
        On the left a password read as a String: it lands on the Java heap, the garbage collector copies it, it cannot
        be wiped, and a heap dump finds three copies. On the right the same password read as a Secret: it lives in
        guarded memory off the heap, is opened only for one callback whose heap copy is zeroed, is wiped when closed,
        and the heap dump finds nothing.
      </desc>
      <rect className="fig-card" x={20} y={10} width={290} height={240} rx={10} />
      <text className="fig-title" x={36} y={36}>
        String password
      </text>
      <rect className="fig-embedded" x={36} y={50} width={258} height={120} rx={6} />
      <text className="fig-small" x={44} y={66}>
        Java heap
      </text>
      <rect className="fig-card" x={330} y={10} width={290} height={240} rx={10} />
      <text className="fig-title" x={346} y={36}>
        Secret password
      </text>
      <rect className="fig-embedded" x={346} y={50} width={258} height={120} rx={6} />
      <text className="fig-small" x={354} y={66}>
        Java heap
      </text>
      <rect className="fig-guarded" x={346} y={182} width={258} height={56} rx={6} />
      <text className="fig-small" x={354} y={198}>
        guarded memory, off the heap
      </text>

      <g className="s0">
        <Chip x={52} y={80} text="hunter2" />
        <Chip x={362} y={206} text="hunter2  PROT_NONE" />
      </g>
      <g className="s1">
        <Chip x={52} y={80} text="hunter2" />
        <Chip x={160} y={108} text="hunter2" />
        <Chip x={70} y={136} text="hunter2" />
        <Chip x={362} y={110} text="char[] copy" kind="open" />
        <Chip x={362} y={206} text="hunter2  PROT_READ" kind="open" />
      </g>
      <g className="s2">
        <Chip x={52} y={80} text="hunter2" />
        <Chip x={160} y={108} text="hunter2" />
        <Chip x={70} y={136} text="hunter2" />
        <text className="fig-small" x={44} y={200}>
          a String cannot be wiped
        </text>
        <Chip x={362} y={110} text="00 00 00 00" kind="wiped" />
        <Chip x={362} y={206} text="00 00 00  wiped" kind="wiped" />
      </g>
      <g className="s3">
        <Chip x={52} y={80} text="hunter2" kind="leak" />
        <Chip x={160} y={108} text="hunter2" kind="leak" />
        <Chip x={70} y={136} text="hunter2" kind="leak" />
        <text className="fig-told fig-missing" x={44} y={210}>
          heap dump: 3 copies found
        </text>
        <text className="fig-told fig-answer" x={362} y={122}>
          heap dump: not found
        </text>
        <Chip x={362} y={206} text="00 00 00  wiped" kind="wiped" />
      </g>
      {captions.map((caption, stop) => (
        <text key={caption} className={`fig-told s${stop}`} x={320} y={282} textAnchor="middle">
          {caption}
        </text>
      ))}
    </svg>
  )
}

/**
 * A slab of guarded memory: a guard page, two secrets, free space and a guard page, with the protection it has at
 * four moments. Idle, every page is closed (PROT_NONE); during withChars the slab is readable and the callback gets a
 * heap copy; when it returns the copy is zeroed and the pages close; an overrun past the slab faults on the guard
 * page. Under it, what holds for every page: locked, out of core dumps and children, out of the kernel's map.
 */
export function GuardedMemoryFigure(): React.ReactElement {
  const captions = [
    'Idle: every page is closed to every access (PROT_NONE)',
    'withChars: the slab is readable while the callback runs',
    'The callback returns: its copy is zeroed, the pages close',
    'A read past the slab hits the guard page and faults',
  ]
  const block = (x: number, label: string, kind: 'plain' | 'open' | 'free', w = 130) => (
    <g>
      <rect className={kind === 'open' ? 'fig-bar-on' : 'fig-bar'} x={x} y={52} width={w} height={46} />
      <text className={kind === 'free' ? 'fig-small' : undefined} x={x + w / 2} y={80} textAnchor="middle">
        {label}
      </text>
    </g>
  )
  return (
    <svg className="fig" viewBox="0 0 640 270" role="img" aria-labelledby="fig-slab-title fig-slab-desc">
      <title id="fig-slab-title">A slab of guarded memory</title>
      <desc id="fig-slab-desc">
        A slab of native memory: a guard page, the secret db.password, the secret api-token, free space and a guard
        page. Idle, every page is closed. During withChars the slab is readable and the callback gets a copy on the
        heap; when the callback returns, the copy is zeroed and the pages close again. A read past the end of the slab
        reaches the guard page and faults. Every page is locked against swap, left out of core dumps and forked
        children, and on Linux taken out of the kernel's direct map with memfd_secret.
      </desc>
      <defs>
        <pattern id="fig-hatch" width={8} height={8} patternUnits="userSpaceOnUse">
          <path className="fig-hatch-line" d="M0 8L8 0M-2 2L2 -2M6 10L10 6" />
        </pattern>
      </defs>
      <text className="fig-small" x={20} y={40}>
        guard page
      </text>
      <text className="fig-small" x={620} y={40} textAnchor="end">
        guard page
      </text>
      <rect className="fig-guard" x={20} y={52} width={60} height={46} fill="url(#fig-hatch)" />
      <rect className="fig-guard" x={560} y={52} width={60} height={46} fill="url(#fig-hatch)" />

      <g className="s0">
        {block(80, 'db.password', 'plain')}
        {block(210, 'api-token', 'plain')}
        {block(340, 'free', 'free', 220)}
        <text className="fig-small" x={320} y={120} textAnchor="middle">
          PROT_NONE
        </text>
      </g>
      <g className="s1">
        {block(80, 'db.password', 'open')}
        {block(210, 'api-token', 'plain')}
        {block(340, 'free', 'free', 220)}
        <path className="fig-arrow" d="M145 102V140" />
        <path className="fig-arrow" d="M140 135l5 6 5-6" />
        <Chip x={92} y={146} text="char[] on the heap" kind="open" />
        <text className="fig-small fig-answer" x={330} y={162}>
          PROT_READ, this thread, this call
        </text>
      </g>
      <g className="s2">
        {block(80, 'db.password', 'plain')}
        {block(210, 'api-token', 'plain')}
        {block(340, 'free', 'free', 220)}
        <Chip x={92} y={146} text="00 00 00 00 00" kind="wiped" />
        <text className="fig-small" x={330} y={162}>
          PROT_NONE again
        </text>
      </g>
      <g className="s3">
        {block(80, 'db.password', 'plain')}
        {block(210, 'api-token', 'plain')}
        {block(340, 'free', 'free', 220)}
        <rect className="fig-leak" x={560} y={52} width={60} height={46} />
        <line className="fig-link" x1={275} y1={112} x2={584} y2={112} />
        <path className="fig-arrow" d="M584 112V102" />
        <text className="fig-told fig-missing" x={620} y={138} textAnchor="end">
          fault: the process stops
        </text>
      </g>
      {captions.map((caption, stop) => (
        <text key={caption} className={`fig-told s${stop}`} x={320} y={198} textAnchor="middle">
          {caption}
        </text>
      ))}
      {[
        ['mlock', 'never swapped'],
        ['MADV_DONTDUMP', 'not in a core dump'],
        ['WIPEONFORK', 'not in a child'],
        ['memfd_secret', "not in the kernel's map"],
      ].map(([call, effect], i) => (
        <g key={call}>
          <rect className="fig-card" x={20 + i * 152} y={218} width={144} height={44} rx={6} />
          <text className="fig-small fig-title" x={92 + i * 152} y={236} textAnchor="middle">
            {call}
          </text>
          <text className="fig-small" x={92 + i * 152} y={252} textAnchor="middle">
            {effect}
          </text>
        </g>
      ))}
    </svg>
  )
}

/**
 * Two ways to send a request with a token over TLS. The JDK's: the token is copied into a byte[] and SSLEngine
 * encrypts through heap buffers, so the plaintext is on the heap twice. The secrets client's: the request is built in
 * guarded memory and OpenSSL encrypts straight out of it into a memory BIO, so only ciphertext leaves native memory.
 */
export function TlsFigure(): React.ReactElement {
  const xs = [20, 180, 340, 500]
  return (
    <svg className="fig" viewBox="0 0 640 250" role="img" aria-labelledby="fig-tls-title fig-tls-desc">
      <title id="fig-tls-title">TLS without the heap</title>
      <desc id="fig-tls-desc">
        Above, the JDK's way: the request with its token is copied into a byte array on the heap, and SSLEngine
        encrypts it through heap buffers before the socket, so the plaintext is on the heap. Below, the secrets
        client's way: the request is built in guarded memory, OpenSSL encrypts straight out of it with SSL_write_ex into
        a memory BIO, and only ciphertext reaches the socket. The response takes the same path back.
      </desc>
      <text className="fig-small" x={20} y={22}>
        The JDK: HttpClient and SSLEngine
      </text>
      <Stage x={xs[0]} y={32} title="token" note="in a Secret" kind="open" />
      <Stage x={xs[1]} y={32} title="byte[]" note="plaintext on the heap" kind="leak" />
      <Stage x={xs[2]} y={32} title="SSLEngine" note="heap buffers" kind="leak" />
      <Stage x={xs[3]} y={32} title="socket" note="ciphertext" />
      {[0, 1, 2].map((i) => (
        <Flow key={i} x1={xs[i] + 122} x2={xs[i + 1] - 2} y={59} />
      ))}
      <text className="fig-small" x={20} y={132}>
        The secrets client: OpenSSL 3 through FFM
      </text>
      <Stage x={xs[0]} y={142} title="request" note="in guarded memory" kind="open" />
      <Stage x={xs[1]} y={142} title="OpenSSL" note="SSL_write_ex" kind="open" />
      <Stage x={xs[2]} y={142} title="memory BIO" note="ciphertext" />
      <Stage x={xs[3]} y={142} title="socket" note="ciphertext" />
      {[0, 1, 2].map((i) => (
        <Flow key={i} x1={xs[i] + 122} x2={xs[i + 1] - 2} y={169} />
      ))}
      <text className="fig-told fig-answer" x={320} y={226} textAnchor="middle">
        The plaintext never leaves native memory, either way
      </text>
    </svg>
  )
}

/**
 * The canary test in four steps: a random canary is written to a file; a child JVM reads it only through the public
 * API and proves it did with a checksum computed in place; the child dumps its whole heap; the test searches the dump
 * for the canary in seven encodings, and finds none.
 */
export function CanaryFigure(): React.ReactElement {
  const steps = [
    ['1 canary', 'random, 48 characters'],
    ['2 child JVM', 'reads it through the API'],
    ['3 heap dump', 'every object, garbage too'],
    ['4 search', 'seven encodings'],
  ]
  const details = [
    ['The test writes a random canary', 'where only the provider will find it:', 'a file, a fake server, a token.'],
    ['A separate JVM reads it through', 'SecretManagerClient, uses it, and prints', 'a CRC32C computed in guarded memory.'],
    ['It closes everything, then dumps its', 'whole heap, unreachable objects', 'included, to a .hprof file.'],
    ['The test searches the dump for the', 'canary in every encoding. One hit', 'fails the build.'],
  ]
  const encodings = ['ASCII, UTF-8', 'UTF-16LE', 'UTF-16BE', 'hex', 'HEX', 'Base64', 'Base64url']
  return (
    <svg className="fig" viewBox="0 0 640 280" role="img" aria-labelledby="fig-canary-title fig-canary-desc">
      <title id="fig-canary-title">The canary test</title>
      <desc id="fig-canary-desc">
        Four steps. The test writes a random 48-character canary. A child JVM reads it only through
        SecretManagerClient and prints a checksum computed in guarded memory, to prove it read it. The child dumps its
        whole heap, unreachable objects included. The test searches the dump for the canary in ASCII and UTF-8,
        UTF-16 in both byte orders, hex in lower and upper case, Base64 and Base64url, and finds no copy.
      </desc>
      {steps.map(([title, note], i) => (
        <g key={title}>
          <rect className="fig-card" x={20 + i * 152} y={12} width={144} height={54} rx={8} />
          <rect className={`fig-bar-on s${i}`} x={20 + i * 152} y={12} width={144} height={54} rx={8} />
          <text className="fig-title" x={92 + i * 152} y={35} textAnchor="middle">
            {title}
          </text>
          <text className="fig-small" x={92 + i * 152} y={53} textAnchor="middle">
            {note}
          </text>
        </g>
      ))}
      {details.map((lines, stop) => (
        <g key={lines[0]} className={`s${stop}`}>
          {lines.map((line, i) => (
            <text key={line} className="fig-told" x={20} y={112 + i * 22}>
              {line}
            </text>
          ))}
        </g>
      ))}
      <rect className="fig-embedded" x={340} y={86} width={280} height={186} rx={6} />
      <text className="fig-small" x={352} y={104}>
        searched in heap.hprof
      </text>
      {encodings.map((encoding, i) => (
        <text key={encoding} className="fig-small" x={352} y={128 + i * 21}>
          {encoding}
        </text>
      ))}
      {[0, 1, 2].map((stop) => (
        <g key={stop} className={`s${stop}`}>
          {encodings.map((encoding, i) => (
            <text key={encoding} className="fig-small" x={606} y={128 + i * 21} textAnchor="end">
              …
            </text>
          ))}
        </g>
      ))}
      <g className="s3">
        {encodings.map((encoding, i) => (
          <text key={encoding} className="fig-small fig-answer" x={606} y={128 + i * 21} textAnchor="end">
            no copy
          </text>
        ))}
        <text className="fig-told fig-answer" x={20} y={210}>
          Clean: the build goes on.
        </text>
      </g>
    </svg>
  )
}
