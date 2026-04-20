export type Severity = 'critical' | 'warning' | 'info';
export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface Finding {
  id: string; analyzer: string; severity: Severity; title: string;
  description: string; file: string; line?: number; code?: string; suggestion?: string;
  confidence: ConfidenceLevel; confidenceScore: number; confidenceReason?: string;
}

export interface EndpointInfo {
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'; path: string;
  controller: string; controllerFile: string; handler: string;
  guards: string[]; pipes: string[]; dtoName?: string;
  params: string[]; hasBody: boolean; line: number;
}

export interface ModuleInfo {
  name: string; path: string; hasController: boolean; hasService: boolean;
  hasModule: boolean; hasDtoFolder: boolean; hasSpecFile: boolean;
  controllerFile?: string; serviceFile?: string; moduleFile?: string;
}

export interface AiFinding {
  originalId: string; aiSeverity: string; explanation: string;
  fixCode: string; impact: string; priority: number;
}

export interface AiReview {
  executiveSummary: string; overallRiskScore: number;
  overallRiskLevel: string; prioritizedFindings: AiFinding[];
}

export interface ScanSummary {
  critical: number; warning: number; info: number;
  totalFiles: number; totalModules: number; totalEndpoints: number;
  scanDurationMs: number;
}

export interface ScanReport {
  id: string; repoUrl: string; branch: string; scannedAt: string;
  summary: ScanSummary; findings: Finding[]; endpoints: EndpointInfo[];
  modules: ModuleInfo[]; aiReview?: AiReview;
}

export interface ScanRequest {
  repoUrl: string; branch: string; pat?: string;
}
