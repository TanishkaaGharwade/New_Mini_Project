export const dummyStats = {
  totalPackets: 14872,
  totalAttacks: 37,
  blockedIPs: 12,
  threatLevel: 8.2,
};

// 20 NSL-KDD attack label badge colors
export const ATTACK_BADGE_COLORS = {
  "normal":          "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30",
  "neptune":         "bg-red-500/20 text-red-300 border border-red-500/30",
  "nmap":            "bg-orange-500/20 text-orange-300 border border-orange-500/30",
  "portsweep":       "bg-orange-500/20 text-orange-300 border border-orange-500/30",
  "ipsweep":         "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30",
  "satan":           "bg-red-600/20 text-red-400 border border-red-600/30",
  "back":            "bg-red-500/20 text-red-300 border border-red-500/30",
  "smurf":           "bg-red-700/20 text-red-400 border border-red-700/30",
  "teardrop":        "bg-purple-500/20 text-purple-300 border border-purple-500/30",
  "pod":             "bg-purple-500/20 text-purple-300 border border-purple-500/30",
  "land":            "bg-rose-500/20 text-rose-300 border border-rose-500/30",
  "buffer_overflow": "bg-amber-500/20 text-amber-300 border border-amber-500/30",
  "rootkit":         "bg-red-800/20 text-red-400 border border-red-800/30",
  "guess_passwd":    "bg-pink-500/20 text-pink-300 border border-pink-500/30",
  "ftp_write":       "bg-sky-500/20 text-sky-300 border border-sky-500/30",
  "multihop":        "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30",
  "spy":             "bg-violet-500/20 text-violet-300 border border-violet-500/30",
  "warezclient":     "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30",
  "warezmaster":     "bg-cyan-600/20 text-cyan-400 border border-cyan-600/30",
  "phf":             "bg-fuchsia-500/20 text-fuchsia-300 border border-fuchsia-500/30",
};

export const dummyThreats = [
  { id: 1, timestamp: "2026-07-31T20:01:00Z", src_ip: "192.168.1.105", src_port: "54321", dst_ip: "192.168.1.20", dst_port: "80", attack_type: "neptune", protocol: "TCP", blocked: true, packet_count: 511 },
  { id: 2, timestamp: "2026-07-31T20:02:00Z", src_ip: "192.168.1.88",  src_port: "12000", dst_ip: "192.168.1.20", dst_port: "443",attack_type: "nmap",    protocol: "TCP", blocked: true, packet_count: 210 },
  { id: 3, timestamp: "2026-07-31T20:03:00Z", src_ip: "10.0.0.55",    src_port: "8080",  dst_ip: "192.168.1.20", dst_port: "22", attack_type: "portsweep",protocol: "TCP", blocked: true, packet_count: 88  },
  { id: 4, timestamp: "2026-07-31T20:04:00Z", src_ip: "192.168.1.10", src_port: "49200", dst_ip: "192.168.1.20", dst_port: "80", attack_type: "normal",   protocol: "TCP", blocked: false,packet_count: 12  },
  { id: 5, timestamp: "2026-07-31T20:05:00Z", src_ip: "192.168.1.66", src_port: "33100", dst_ip: "192.168.1.20", dst_port: "53", attack_type: "satan",    protocol: "UDP", blocked: true, packet_count: 45  },
  { id: 6, timestamp: "2026-07-31T20:06:00Z", src_ip: "192.168.1.200",src_port: "41000", dst_ip: "192.168.1.20", dst_port: "80", attack_type: "smurf",    protocol: "ICMP",blocked: true, packet_count: 1000},
  { id: 7, timestamp: "2026-07-31T20:07:00Z", src_ip: "10.0.0.99",   src_port: "5000",  dst_ip: "192.168.1.20", dst_port: "80", attack_type: "normal",   protocol: "TCP", blocked: false,packet_count: 8   },
  { id: 8, timestamp: "2026-07-31T20:08:00Z", src_ip: "192.168.1.77", src_port: "21000", dst_ip: "192.168.1.20", dst_port: "21", attack_type: "guess_passwd",protocol:"TCP",blocked: true, packet_count: 200},
];
