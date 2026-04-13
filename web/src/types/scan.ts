export interface FindingInstance {
  URL: string;
  Method: string;
  Evidence: string;
}

export interface GroupedFinding {
  Title: string;
  Description: string;
  Severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  OWASP: string;
  Remediation: string;
  Endpoints: string[];
}

export interface Endpoint {
  URL: string;
  Method: string;
  Params: string[];
}

export interface ScanResult {
  Target: string;
  ScannedAt: string;
  Duration: number; 
  StatusCode: number;
  Status: string;
  AllHeaders: Record<string, string[]>;
  Findings: GroupedFinding[];
  Endpoints: Endpoint[];
  SeverityCounts: Record<string, number>;
}
