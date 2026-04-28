// Report Generator MCP Tool
// Exposes generate_hunt_report as an MCP tool
// Calls docx-builder to produce a Word document on the user's Desktop

import { defineTool, type ToolDefinition } from '../registry.js';
import { generateHuntReport, type HuntReport } from './docx-builder.js';

const generateHuntReportTool: ToolDefinition = defineTool({
  name: 'generate_hunt_report',
  description:
    'Generates a formatted Word document (.docx) threat hunt report from structured hunt card data. ' +
    'Saves the file to C:\\Users\\{username}\\Desktop\\Threat Hunting Reports\\{Actor}_{Date}.docx. ' +
    'Creates the output folder automatically if it does not exist. ' +
    'Input must include report metadata and an array of hunt cards (one per technique). ' +
    'Each card must contain: hunt_id, hypothesis_name, objective, priority, confidence, ' +
    'mitre_mapping (with group aliases), prerequisites, expected_artifacts, risks, ' +
    'log_sources, coverage_status, query (Sigma YAML), true_positive_criteria, and escalation_path. ' +
    'Returns the full output file path on success.',
  inputSchema: {
    type: 'object',
    properties: {
      title: {
        type: 'string',
        description: 'Report title, e.g. "Threat Hunt Report — MuddyWater (2026-03-11)"',
      },
      actor: {
        type: 'string',
        description: 'Canonical threat actor name, e.g. "MuddyWater"',
      },
      actor_id: {
        type: 'string',
        description: 'MITRE ATT&CK group ID, e.g. "G0069"',
      },
      analyst: {
        type: 'string',
        description: 'Analyst name or team name',
      },
      date: {
        type: 'string',
        description: 'Report date in YYYY-MM-DD format',
      },
      classification: {
        type: 'string',
        description: 'Classification marking, e.g. "TLP:AMBER"',
      },
      executive_summary: {
        type: 'string',
        description: '2–3 sentence executive summary of coverage state and key risks',
      },
      cards: {
        type: 'array',
        description: 'Array of hunt card objects, one per technique hunted',
        items: {
          type: 'object',
          properties: {
            hunt_id: { type: 'string', description: 'e.g. "HUNT-001"' },
            hypothesis_name: { type: 'string' },
            objective: { type: 'string' },
            priority: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
            confidence: { type: 'string', enum: ['High', 'Medium', 'Low'] },
            mitre_mapping: {
              type: 'object',
              properties: {
                group_name:     { type: 'string' },
                group_id:       { type: 'string' },
                aliases:        { type: 'array', items: { type: 'string' } },
                tactic:         { type: 'string' },
                technique_id:   { type: 'string' },
                technique_name: { type: 'string' },
                sub_technique:  { type: 'string' },
                software:       { type: 'array', items: { type: 'string' } },
              },
              required: ['group_name', 'group_id', 'aliases', 'tactic', 'technique_id', 'technique_name'],
            },
            prerequisites:  { type: 'array', items: { type: 'string' } },
            expected_artifacts: {
              type: 'object',
              properties: {
                process: { type: 'string' },
                parent:  { type: 'string' },
                cli:     { type: 'string' },
                network: { type: 'string' },
                files:   { type: 'string' },
              },
            },
            risks: {
              type: 'object',
              properties: {
                fp_risk:          { type: 'string' },
                evasion_risk:     { type: 'string' },
                operational_risk: { type: 'string' },
              },
              required: ['fp_risk', 'evasion_risk', 'operational_risk'],
            },
            log_sources: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  log_source:  { type: 'string' },
                  event_id:    { type: 'string' },
                  platform:    { type: 'string' },
                  must_enable: { type: 'string' },
                },
                required: ['log_source', 'event_id', 'platform', 'must_enable'],
              },
            },
            coverage_status: { type: 'string', enum: ['COVERED', 'PARTIAL', 'GAP'] },
            validation_scores: {
              type: 'object',
              properties: {
                evasion: { type: 'number' },
                fields:  { type: 'number' },
                paths:   { type: 'number' },
                fp:      { type: 'number' },
                syntax:  { type: 'number' },
              },
            },
            query: {
              type: 'string',
              description: 'Full Sigma rule YAML, or GAP note if no rule exists',
            },
            true_positive_criteria: {
              type: 'object',
              properties: {
                confirmed:   { type: 'array', items: { type: 'string' } },
                investigate: { type: 'array', items: { type: 'string' } },
                not_tp:      { type: 'array', items: { type: 'string' } },
              },
              required: ['confirmed', 'investigate', 'not_tp'],
            },
            escalation_path: { type: 'array', items: { type: 'string' } },
          },
          required: [
            'hunt_id', 'hypothesis_name', 'objective', 'priority', 'confidence',
            'mitre_mapping', 'prerequisites', 'expected_artifacts', 'risks',
            'log_sources', 'coverage_status', 'query', 'true_positive_criteria',
            'escalation_path',
          ],
        },
      },
    },
    required: ['title', 'actor', 'actor_id', 'analyst', 'date', 'classification', 'executive_summary', 'cards'],
  },
  handler: async (args) => {
    const report = args as unknown as HuntReport;

    if (!report.cards || report.cards.length === 0) {
      return { error: true, message: 'No hunt cards provided. Add at least one card.' };
    }

    const outputPath = await generateHuntReport(report);
    return {
      success: true,
      output_path: outputPath,
      cards_written: report.cards.length,
      message: `Report saved to: ${outputPath}`,
    };
  },
});

export const reportGeneratorTools: ToolDefinition[] = [generateHuntReportTool];
export const reportGeneratorToolCount = reportGeneratorTools.length;
