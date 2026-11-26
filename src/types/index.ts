export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanStatus = 'idle' | 'queued' | 'running' | 'completed' | 'failed' | 'paused' | 'cancelled';

export type ScanType = 'full' | 'quick' | 'network' | 'web' | 'api' | 'compliance';

export type ScanAuthorizationMode = 'allow_list' | 'on_demand';

export interface CreateScanInput {
  name?: string;
  targetUrl: string;
  type: ScanType;
  authorizationMode?: ScanAuthorizationMode;
  authorizationConfirmed?: boolean;
}

export type VulnStatus =
  | 'open'
  | 'in_progress'
  | 'resolved'
  | 'false_positive'
  | 'accepted';

export interface Vulnerability {
  id: string;
  title: string;
  name?: string;
  description: string;
  severity: Severity;
  cve?: string;
  cvss: number;
  cvssScore?: number;
  cvssVector?: string;
  target: string;
  asset?: string;
  assetId?: string;
  assetName?: string;
  assetTarget?: string;
  path?: string;
  status: VulnStatus;
  discoveredAt: string;
  remediation?: string;
  category?: string;
  evidence?: string;
  affectedAssetId?: string;
  port?: number;
  protocol?: string;
  service?: string;
  references?: string[];
}


export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface Scan {
  id: string;
  name: string;
  targetUrl: string;
  type: ScanType;
  status: ScanStatus;
  progress: number;
  startedAt: string;
  completedAt?: string;
  duration?: string;
  findings: FindingsCount;
  vulnerabilities?: Vulnerability[];
  logs?: string[];
  errorMessage?: string;
}

export interface ScanResult {
  id: string;
  scan_id: string;
  host_address: string;
  hostname?: string | null;
  host_name?: string | null;
  host_state?: string | null;
  port?: number | null;
  protocol?: string | null;
  port_state?: string | null;
  service_name?: string | null;
  service_product?: string | null;
  service_version?: string | null;
  service_extra_info?: string | null;
  created_at: string;
}

export type DiscoveryTargetType = 'cidr' | 'range';

export interface DiscoveryRun {
  id: string;
  target: string;
  target_kind: DiscoveryTargetType;
  range_start?: string | null;
  range_end?: string | null;
  authorization_mode: ScanAuthorizationMode;
  authorization_confirmed: boolean;
  authorization_confirmed_at?: string | null;
  status: Exclude<ScanStatus, 'idle' | 'paused'>;
  progress: number;
  partial_results: boolean;
  error_message?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface DiscoveredHost {
  id: string;
  discovery_id: string;
  ip_address: string;
  hostname?: string | null;
  mac_address?: string | null;
  vendor?: string | null;
  discovery_status: 'responding' | 'observed';
  last_seen_at: string;
  authorized: boolean;
}

export interface CreateDiscoveryInput {
  target_type: DiscoveryTargetType;
  authorization_mode: ScanAuthorizationMode;
  cidr?: string;
  start_ip?: string;
  end_ip?: string;
  authorization_confirmed: boolean;
}

export interface ScanReportPort {
  id: string;
  host_address: string;
  hostname?: string | null;
  host_state: string;
  port?: number | null;
  protocol?: string | null;
  state?: string | null;
  service_name?: string | null;
  product?: string | null;
  version?: string | null;
  extra_information?: string | null;
}

export interface ScanReportFinding {
  id: string;
  title: string;
  severity: Severity;
  cve_id?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  affected_target: string;
  port?: number | null;
  service_name?: string | null;
  description?: string | null;
  evidence?: string | null;
  remediation?: string | null;
  status: string;
}

export interface ScanReportDetail {
  scan_id: string;
  target: string;
  status: Exclude<ScanStatus, 'idle' | 'paused'>;
  progress: number;
  scan_profile: string;
  scanner: string;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  error_message?: string | null;
  resolved_addresses: string[];
  authorization_mode?: string | null;
  recorded_configuration?: string | null;
  port_inventory_recorded: boolean;
  summary: {
    total_ports_examined?: number | null;
    recorded_port_entries: number;
    open_ports: number;
    closed_or_filtered_ports: number;
    identified_services: number;
    findings: FindingsCount;
  };
  ports: ScanReportPort[];
  findings: ScanReportFinding[];
  limitations: string[];
}

export type AssetType = 'server' | 'workstation' | 'network' | 'web' | 'cloud';

export interface Asset {
  id: string;
  name: string;
  ip: string;
  type: AssetType;
  os?: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  status: 'online' | 'offline' | 'scanning' | 'unscanned';
  vulnerabilitiesCount: FindingsCount;
  lastScanned: string;
  tags: string[];
  owner?: string;
  location?: string;
  created_at?: string;
  updated_at?: string;
  openPortsCount?: number;
}

export interface Report {
  id: string;
  reportCode?: string;
  name: string;
  target: string;
  type: 'executive' | 'technical' | 'compliance' | 'network' | 'delta';
  scanDate: string;
  status: 'ready' | 'generating' | 'failed';
  format: 'PDF' | 'CSV' | 'JSON' | 'pdf' | 'csv' | 'json';
  findingsSummary: FindingsCount;
  fileSize: string;
  downloadUrl?: string;
  securityScore?: number;
  totalAssets?: number;
  totalScans?: number;
  snapshotData?: any;
}

export type IntegrationProvider = 'jira' | 'slack' | 'splunk';

export interface PlatformPreferences {
  max_concurrent_scans: number;
  scanner_rate_limit_per_minute: number;
  session_timeout_minutes: number;
  accent_color: string;
}

export interface SecretStatus {
  configured: boolean;
  masked_hint: string | null;
  updated_at: string | null;
}

export interface PlatformSettings {
  preferences: PlatformPreferences;
  integrations: Record<IntegrationProvider, SecretStatus>;
  api_key: SecretStatus;
  runtime: {
    environment: string;
    app_version: string;
    nmap_available: boolean;
    runtime_max_concurrent_scans: number;
    runtime_rate_limit_per_minute: number;
    concurrency_restart_required: boolean;
    rate_limit_enforced: boolean;
    session_enforcement_available: boolean;
    api_key_authentication_available: boolean;
    integration_encryption_configured: boolean;
  };
}

export interface DashboardStats {
  totalScans: number;
  activeScans: number;
  completedScans: number;
  failedScans: number;
  cancelledScans: number;
  totalAssets: number;
  discoveredHosts: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  resolvedCount: number;
  averageRiskScore: number;
  securityScore: number;
}

export interface DashboardTelemetry {
  stats: DashboardStats;
  trendData: Array<{
    date: string;
    critical: number;
    high: number;
    medium: number;
    resolved: number;
  }>;
  severityDistribution: Array<{
    name: string;
    value: number;
    color: string;
  }>;
  categoryData: Array<{
    category: string;
    count: number;
    color: string;
  }>;
  recentScans: Scan[];
  recentVulnerabilities: Vulnerability[];
}

export interface AuthorizedTarget {
  id: string;
  target: string;
  description?: string | null;
  is_enabled: boolean;
  created_at: string;
}
