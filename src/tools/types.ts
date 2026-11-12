import type { ComponentType } from 'react';

export interface CategoryDef {
  id: string;
  title: string;
  blurb: string;
}

export interface ToolDef {
  /** URL segment, e.g. "nmap-command-builder". */
  path: string;
  /** Display name shown in the sidebar, card grid and page heading. */
  name: string;
  /** One-line description used on cards and under the page heading. */
  description: string;
  /** Category id — must exist in CATEGORIES. */
  category: string;
  /** Extra search terms for the command palette. */
  keywords?: string[];
  component: ComponentType;
}

/** Sidebar + home ordering, mirroring the it-tools category rhythm. */
export const CATEGORIES: CategoryDef[] = [
  { id: 'recon', title: 'Recon', blurb: 'Passive mapping, wordlists and target triage.' },
  { id: 'network', title: 'Network', blurb: 'Scanning, pivoting and transport-layer tooling.' },
  { id: 'web', title: 'Web', blurb: 'Injection payloads, header abuse and request crafting.' },
  { id: 'tokens', title: 'Web tokens', blurb: 'JWT inspection, forging and signature recovery.' },
  { id: 'exploit', title: 'Exploit', blurb: 'Payload scaffolding, privesc and AD tradecraft.' },
  { id: 'credential', title: 'Credentials', blurb: 'Hash identification, cracking plans and credential generation.' },
  { id: 'crypto', title: 'Crypto', blurb: 'Digests, key derivation, XOR and classical ciphers.' },
  { id: 'encoding', title: 'Encoding', blurb: 'Encode, escape and obfuscate payloads for transport.' },
  { id: 'social', title: 'Social engineering', blurb: 'Pretext design, lures and canary tokens.' },
  { id: 'reporting', title: 'Reporting', blurb: 'Scoring, findings and clean evidence handling.' },
];

export const categoryTitle = (id: string): string => CATEGORIES.find((c) => c.id === id)?.title ?? id;
