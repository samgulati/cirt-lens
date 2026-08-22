export interface SecurityEvent {id:string;timestamp:string;source:'Identity'|'Endpoint'|'Network'|'Cloud';user?:string;host?:string;source_ip?:string;activity:string;risk_score:number;risk_flags:string[];raw:Record<string,unknown>}
export interface Technique {id:string;name:string;reason:string;evidence_ids:string[]}
export interface RecommendedAction {action:string;reason:string;risk_reduction:string;reduction_points:number;objectives:string[];status:'PENDING'|'EXECUTED';executed_at?:string;analyst?:string}
export type RiskBreakdown=Record<string,number>;
export type Disposition='UNSET'|'TRUE_POSITIVE'|'FALSE_POSITIVE'|'BENIGN_POSITIVE';
export interface DetectionFinding {event_id:string;rule_id:string;rule_version:string;flag:string;risk_contribution:number;reason:string;metadata:Record<string,unknown>}
export interface CorrelationNode {id:string;type:string;value:string;evidence_ids:string[];risk_flags:string[]}
export interface CorrelationEdge {id:string;from:string;to:string;relationship:string;score:number;evidence_ids:string[]}
export interface RiskHistory {timestamp:string;original_risk:number;residual_risk:number;reason:string}
export interface AnalystNote {id:number;analyst:string;text:string;timestamp:string}
export interface CorrelationGraph {nodes:CorrelationNode[];edges:CorrelationEdge[]}
export interface Incident {id:string;title:string;incident_type:string;description:string;created_at:string;updated_at:string;severity:string;status:string;disposition:Disposition;risk_score:number;residual_risk_score:number;confidence_score:number;confidence_breakdown:Record<string,number>;primary_user?:string;primary_host?:string;source_ips:string[];affected_assets:string[];event_ids:string[];techniques:Technique[];recommended_actions:RecommendedAction[];root_cause:string;score_breakdown:RiskBreakdown;assigned_to?:string;events:SecurityEvent[];graph:CorrelationGraph;notes:AnalystNote[];bookmarks:{id:number;event_id:string;analyst:string;note:string;timestamp:string}[];risk_history:RiskHistory[];detection_findings:DetectionFinding[]}
export interface ActivityRecord {id:number;timestamp:string;analyst:string;action:string;incident_id:string;result:string;details:string}
export interface AIResponse {answer:string;mode:'local_deterministic'|'openai'|'local_fallback';validated:boolean;cited_event_ids:string[];latency_ms:number}
export interface SearchResults {incidents:Incident[];users:string[];hosts:string[];ips:string[];events:SecurityEvent[]}
export interface EntityGraphNode {type:string;value:string;eventIds:string[];riskFlags:string[]}
export interface DashboardResponse {kpis:{open_incidents:number;critical_incidents:number;events_analyzed:number;detection_findings:number;mean_triage_time:string};severity:Record<string,number>;trend:{hour:string;incidents:number}[];sources:Record<string,number>;recent:Incident[]}
export interface Playbook {id:string;name:string;description:string;conditions:string[];required_objectives:string[];actions:string[]}
export interface SearchResult {label:string;sub:string;path:string}
