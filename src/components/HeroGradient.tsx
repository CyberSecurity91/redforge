/**
 * Sidebar header artwork: the it-tools hero gradient, re-tinted for a red-team
 * identity. Pure SVG so it costs no network request and stays crisp at any DPI.
 */
export function HeroGradient() {
  return (
    <svg
      className="absolute inset-0 h-full w-full"
      viewBox="0 0 240 125"
      preserveAspectRatio="none"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id="rf-hero-base" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#4a0b12" />
          <stop offset="45%" stopColor="#8e1420" />
          <stop offset="100%" stopColor="#7a0f1c" />
        </linearGradient>
        <linearGradient id="rf-hero-swoop" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#b3162a" stopOpacity="0.95" />
          <stop offset="60%" stopColor="#8c0f1f" stopOpacity="0.75" />
          <stop offset="100%" stopColor="#4c0710" stopOpacity="0.9" />
        </linearGradient>
        <radialGradient id="rf-hero-glow" cx="18%" cy="14%" r="80%">
          <stop offset="0%" stopColor="#ff5a66" stopOpacity="0.42" />
          <stop offset="100%" stopColor="#ff5a66" stopOpacity="0" />
        </radialGradient>
      </defs>

      <rect width="240" height="125" fill="url(#rf-hero-base)" />
      <path d="M0 125 C 60 95, 120 88, 170 62 C 205 44, 225 26, 240 8 L240 125 Z" fill="url(#rf-hero-swoop)" />
      <path
        d="M0 125 C 70 108, 118 74, 168 52 C 202 37, 224 22, 240 0 L240 125 Z"
        fill="#2b0509"
        fillOpacity="0.35"
      />
      <rect width="240" height="125" fill="url(#rf-hero-glow)" />
    </svg>
  );
}
