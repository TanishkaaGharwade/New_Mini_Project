/**
 * Canonical label registry for CyberSentinel (CICIDS2017 model).
 * 7 attack classes + Benign (never stored, but kept for reference).
 *
 * Each entry has:
 *   displayName  — human-readable label shown in badges and filters
 *   color        — accent hex used for the badge text / border
 *   bg           — translucent background for the badge
 *   border       — border colour string
 *   severity     — LOW | MEDIUM | HIGH | CRITICAL (used as fallback when no AI explanation)
 *   description  — one-line plain English description shown in tooltips / settings
 */
export const LABELS = {
  DoS: {
    displayName: 'DoS',
    color: '#ff4560',
    bg: 'rgba(255,69,96,0.13)',
    border: 'rgba(255,69,96,0.3)',
    severity: 'CRITICAL',
    description: 'Denial-of-Service flood overwhelming CPU, memory or bandwidth.',
  },
  DDoS: {
    displayName: 'DDoS',
    color: '#ff2244',
    bg: 'rgba(255,34,68,0.13)',
    border: 'rgba(255,34,68,0.3)',
    severity: 'CRITICAL',
    description: 'Distributed Denial-of-Service from multiple sources simultaneously.',
  },
  PortScan: {
    displayName: 'Port Scan',
    color: '#ffa500',
    bg: 'rgba(255,165,0,0.13)',
    border: 'rgba(255,165,0,0.3)',
    severity: 'HIGH',
    description: 'Systematic probe of destination ports to find open services.',
  },
  BruteForce: {
    displayName: 'Brute Force',
    color: '#f97316',
    bg: 'rgba(249,115,22,0.13)',
    border: 'rgba(249,115,22,0.3)',
    severity: 'HIGH',
    description: 'Repeated login attempts against FTP, SSH or other services.',
  },
  Botnet: {
    displayName: 'Botnet',
    color: '#a855f7',
    bg: 'rgba(168,85,247,0.13)',
    border: 'rgba(168,85,247,0.3)',
    severity: 'HIGH',
    description: 'Traffic pattern consistent with bot command-and-control activity.',
  },
  SynFlood: {
    displayName: 'SYN Flood',
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.13)',
    border: 'rgba(239,68,68,0.3)',
    severity: 'CRITICAL',
    description: 'Half-open TCP SYN packets exhausting server connection tables.',
  },
  IcmpFlood: {
    displayName: 'ICMP Flood',
    color: '#ec4899',
    bg: 'rgba(236,72,153,0.13)',
    border: 'rgba(236,72,153,0.3)',
    severity: 'HIGH',
    description: 'High-volume ICMP echo (ping) flood against the host.',
  },
  // Reference only — benign flows are never stored in Firestore
  Benign: {
    displayName: 'Benign',
    color: '#00e396',
    bg: 'rgba(0,227,150,0.13)',
    border: 'rgba(0,227,150,0.3)',
    severity: 'LOW',
    description: 'Normal traffic (never stored as a threat record).',
  },
}

/** Ordered list used in filters, settings and charts */
export const ATTACK_LABELS = ['DoS', 'DDoS', 'PortScan', 'BruteForce', 'Botnet', 'SynFlood', 'IcmpFlood']

/**
 * Returns the style props for a label badge.
 * Falls back to a neutral grey if the label is unknown.
 */
export function getLabelStyle(label) {
  const entry = LABELS[label]
  if (!entry) {
    return {
      color: '#94a3b8',
      bg: 'rgba(148,163,184,0.1)',
      border: 'rgba(148,163,184,0.25)',
      displayName: label || 'Unknown',
      severity: 'MEDIUM',
      description: 'Unrecognised attack label.',
    }
  }
  return entry
}
