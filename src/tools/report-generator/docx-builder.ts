// Word Document Builder for Threat Hunt Reports
// Uses docx v9 to produce formatted .docx files
// Output: C:\Users\{user}\Desktop\Threat Hunting Reports\{Actor}_{Date}.docx

import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  Table,
  TableRow,
  TableCell,
  HeadingLevel,
  AlignmentType,
  BorderStyle,
  WidthType,
  ShadingType,
  PageBreak,
  UnderlineType,
} from 'docx';
import fs from 'fs';
import path from 'path';
import os from 'os';

// ── Types ──────────────────────────────────────────────────────────────────

export interface LogSourceRow {
  log_source: string;
  event_id: string;
  platform: string;
  must_enable: string;
}

export interface HuntCardRisks {
  fp_risk: string;
  evasion_risk: string;
  operational_risk: string;
}

export interface MitreMapping {
  group_name: string;
  group_id: string;
  aliases: string[];
  tactic: string;
  technique_id: string;
  technique_name: string;
  sub_technique?: string;
  software: string[];
}

export interface HuntCard {
  hunt_id: string;
  hypothesis_name: string;
  objective: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'High' | 'Medium' | 'Low';
  mitre_mapping: MitreMapping;
  prerequisites: string[];
  expected_artifacts: {
    process?: string;
    parent?: string;
    cli?: string;
    network?: string;
    files?: string;
  };
  risks: HuntCardRisks;
  log_sources: LogSourceRow[];
  coverage_status: 'COVERED' | 'PARTIAL' | 'GAP';
  validation_scores?: {
    evasion: number;
    fields: number;
    paths: number;
    fp: number;
    syntax: number;
  };
  query: string;
  true_positive_criteria: {
    confirmed: string[];
    investigate: string[];
    not_tp: string[];
  };
  escalation_path: string[];
}

export interface HuntReport {
  title: string;
  actor: string;
  actor_id: string;
  analyst: string;
  date: string;
  classification: string;
  executive_summary: string;
  cards: HuntCard[];
}

// ── Colour palette ─────────────────────────────────────────────────────────

const COLOURS = {
  critical:    'C0392B',
  high:        'E67E22',
  medium:      'F1C40F',
  low:         '27AE60',
  covered:     '1E8449',
  partial:     'D4AC0D',
  gap:         'C0392B',
  header_bg:   '1B2631',
  header_text: 'FFFFFF',
  row_alt:     'EBF5FB',
  border:      'AEB6BF',
  code_bg:     'F2F3F4',
  amber:       'E67E22',
};

const priorityColour = (p: string) => {
  switch (p.toUpperCase()) {
    case 'CRITICAL': return COLOURS.critical;
    case 'HIGH':     return COLOURS.high;
    case 'MEDIUM':   return COLOURS.medium;
    default:         return COLOURS.low;
  }
};

const coverageColour = (s: string) => {
  switch (s.toUpperCase()) {
    case 'COVERED': return COLOURS.covered;
    case 'PARTIAL': return COLOURS.partial;
    default:        return COLOURS.gap;
  }
};

// ── Helpers ────────────────────────────────────────────────────────────────

function heading1(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text, bold: true, color: COLOURS.header_bg })],
    spacing: { before: 400, after: 200 },
  });
}

function heading2(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text, bold: true })],
    spacing: { before: 300, after: 150 },
  });
}

function heading3(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    children: [new TextRun({ text, bold: true, color: '2C3E50' })],
    spacing: { before: 200, after: 100 },
  });
}

function body(text: string): Paragraph {
  return new Paragraph({
    children: [new TextRun({ text, size: 22 })],
    spacing: { after: 100 },
  });
}

function bullet(text: string, level = 0): Paragraph {
  return new Paragraph({
    bullet: { level },
    children: [new TextRun({ text, size: 22 })],
    spacing: { after: 80 },
  });
}

function codeBlock(text: string): (Paragraph | Table)[] {
  return text.split('\n').map(line =>
    new Paragraph({
      children: [new TextRun({
        text: line || ' ',
        font: 'Courier New',
        size: 18,
        color: '1B2631',
      })],
      shading: { type: ShadingType.SOLID, color: COLOURS.code_bg, fill: COLOURS.code_bg },
      spacing: { after: 0 },
    })
  );
}

function pageBreak(): Paragraph {
  return new Paragraph({ children: [new PageBreak()] });
}

function labelValuePara(label: string, value: string): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({ text: `${label}: `, bold: true, size: 22 }),
      new TextRun({ text: value, size: 22 }),
    ],
    spacing: { after: 80 },
  });
}

function colourBadge(text: string, colour: string): TextRun {
  return new TextRun({
    text: ` ${text} `,
    bold: true,
    color: 'FFFFFF',
    shading: { type: ShadingType.SOLID, color: colour, fill: colour },
  });
}

// ── Table builders ─────────────────────────────────────────────────────────

function borderStyle() {
  return {
    top:    { style: BorderStyle.SINGLE, size: 1, color: COLOURS.border },
    bottom: { style: BorderStyle.SINGLE, size: 1, color: COLOURS.border },
    left:   { style: BorderStyle.SINGLE, size: 1, color: COLOURS.border },
    right:  { style: BorderStyle.SINGLE, size: 1, color: COLOURS.border },
  };
}

function headerCell(text: string): TableCell {
  return new TableCell({
    children: [new Paragraph({
      children: [new TextRun({ text, bold: true, color: COLOURS.header_text, size: 20 })],
      alignment: AlignmentType.LEFT,
    })],
    shading: { type: ShadingType.SOLID, color: COLOURS.header_bg, fill: COLOURS.header_bg },
    borders: borderStyle(),
  });
}

function dataCell(text: string, shade?: string): TableCell {
  return new TableCell({
    children: [new Paragraph({
      children: [new TextRun({ text, size: 20 })],
    })],
    shading: shade
      ? { type: ShadingType.SOLID, color: shade, fill: shade }
      : undefined,
    borders: borderStyle(),
  });
}

function buildTable(headers: string[], rows: string[][]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ children: headers.map(h => headerCell(h)), tableHeader: true }),
      ...rows.map((row, i) =>
        new TableRow({
          children: row.map(cell => dataCell(cell, i % 2 === 1 ? COLOURS.row_alt : undefined)),
        })
      ),
    ],
  });
}

// ── Section builders ───────────────────────────────────────────────────────

function buildCoverPage(report: HuntReport): (Paragraph | Table)[] {
  const aliasText = report.cards[0]?.mitre_mapping?.aliases?.join(' | ') || '';
  return [
    new Paragraph({ spacing: { before: 2000 } }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({
        text: `[${report.classification}]`,
        bold: true, color: COLOURS.amber, size: 24,
      })],
    }),
    new Paragraph({ spacing: { before: 400 } }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({
        text: 'THREAT HUNT REPORT',
        bold: true, size: 52, color: COLOURS.header_bg,
      })],
    }),
    new Paragraph({ spacing: { before: 400 } }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: report.actor, bold: true, size: 36 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `${report.actor_id}`, size: 28, color: '7F8C8D' })],
    }),
    ...(aliasText ? [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: aliasText, size: 20, color: '7F8C8D', italics: true })],
    })] : []),
    new Paragraph({ spacing: { before: 600 } }),
    labelValuePara('Date', report.date),
    labelValuePara('Analyst', report.analyst),
    labelValuePara('Techniques', `${report.cards.length} techniques analysed`),
    labelValuePara('Critical Gaps', `${report.cards.filter(c => c.priority === 'CRITICAL').length} critical`),
    pageBreak(),
  ];
}

function buildExecutiveSummary(report: HuntReport): (Paragraph | Table)[] {
  const covered = report.cards.filter(c => c.coverage_status === 'COVERED').length;
  const partial = report.cards.filter(c => c.coverage_status === 'PARTIAL').length;
  const gap = report.cards.filter(c => c.coverage_status === 'GAP').length;
  const total = report.cards.length;

  const coverageRows = report.cards.map(c => [
    c.hunt_id,
    c.mitre_mapping.technique_id,
    c.mitre_mapping.technique_name,
    c.coverage_status,
    c.priority,
  ]);

  return [
    heading1('Executive Summary'),
    body(report.executive_summary),
    new Paragraph({ spacing: { before: 200 } }),
    new Paragraph({
      children: [
        new TextRun({ text: 'Coverage Score: ', bold: true, size: 22 }),
        new TextRun({ text: `${covered}/${total} techniques have active detections  `, size: 22 }),
        colourBadge(`${gap} GAPS`, COLOURS.gap),
        new TextRun({ text: '  ' }),
        colourBadge(`${partial} PARTIAL`, COLOURS.partial),
        new TextRun({ text: '  ' }),
        colourBadge(`${covered} COVERED`, COLOURS.covered),
      ],
      spacing: { after: 200 },
    }),
    new Paragraph({ spacing: { before: 200 } }),
    heading2('Hunt Priority Order'),
    buildTable(
      ['Hunt ID', 'T-ID', 'Technique', 'Coverage', 'Priority'],
      coverageRows
    ),
    pageBreak(),
  ];
}

function buildHuntCard(card: HuntCard, index: number): (Paragraph | Table)[] {
  const sections: (Paragraph | Table)[] = [];

  // Card header
  sections.push(
    heading1(`${card.hunt_id} — ${card.hypothesis_name}`),
    new Paragraph({
      children: [
        new TextRun({ text: 'Priority: ', bold: true, size: 22 }),
        colourBadge(card.priority, priorityColour(card.priority)),
        new TextRun({ text: '    Confidence: ', bold: true, size: 22 }),
        new TextRun({ text: card.confidence, size: 22 }),
        new TextRun({ text: '    Coverage: ', bold: true, size: 22 }),
        colourBadge(card.coverage_status, coverageColour(card.coverage_status)),
      ],
      spacing: { after: 200 },
    }),
  );

  // 1. Objective
  sections.push(heading3('Objective'), body(card.objective));

  // 2. MITRE Mapping
  sections.push(
    heading3('MITRE Mapping'),
    buildTable(
      ['Field', 'Value'],
      [
        ['Group', `${card.mitre_mapping.group_name} (${card.mitre_mapping.group_id})`],
        ['Aliases', card.mitre_mapping.aliases.join(' | ')],
        ['Tactic', card.mitre_mapping.tactic],
        ['Technique', `${card.mitre_mapping.technique_id} — ${card.mitre_mapping.technique_name}`],
        ['Sub-Technique', card.mitre_mapping.sub_technique || 'N/A'],
        ['Software', card.mitre_mapping.software.join(', ') || 'N/A'],
      ]
    ),
    new Paragraph({ spacing: { after: 160 } }),
  );

  // 3. Hunt Confidence
  sections.push(heading3('Hunt Confidence'), body(card.confidence));

  // 4. Prerequisites
  sections.push(heading3('Prerequisites'));
  card.prerequisites.forEach(p => sections.push(bullet(p)));

  // 5. Expected Artifacts
  sections.push(heading3('Expected Artifacts'));
  const arts = card.expected_artifacts;
  if (arts.process)  sections.push(bullet(`Process: ${arts.process}`));
  if (arts.parent)   sections.push(bullet(`Parent:  ${arts.parent}`));
  if (arts.cli)      sections.push(bullet(`CLI:     ${arts.cli}`));
  if (arts.network)  sections.push(bullet(`Network: ${arts.network}`));
  if (arts.files)    sections.push(bullet(`Files:   ${arts.files}`));

  // 6. Risks
  sections.push(
    heading3('Risks'),
    buildTable(
      ['Risk Type', 'Description'],
      [
        ['FP Risk', card.risks.fp_risk],
        ['Evasion Risk', card.risks.evasion_risk],
        ['Operational Risk', card.risks.operational_risk],
      ]
    ),
    new Paragraph({ spacing: { after: 160 } }),
  );

  // 7. Log Sources
  sections.push(
    heading3('Log Source & Data Source Required'),
    buildTable(
      ['Log Source', 'Event ID', 'Platform', 'Must-Enable Setting'],
      card.log_sources.map(r => [r.log_source, r.event_id, r.platform, r.must_enable])
    ),
    new Paragraph({ spacing: { after: 160 } }),
  );

  // 8. Query
  const valScores = card.validation_scores;
  const valText = valScores
    ? `Evasion ${valScores.evasion}/5 | Fields ${valScores.fields}/5 | Paths ${valScores.paths}/5 | FP ${valScores.fp}/5 | Syntax ${valScores.syntax}/5`
    : 'Not validated';

  sections.push(
    heading3('Detection Query'),
    new Paragraph({
      children: [
        new TextRun({ text: 'Coverage: ', bold: true, size: 20 }),
        colourBadge(card.coverage_status, coverageColour(card.coverage_status)),
        new TextRun({ text: `    Validation: ${valText}`, size: 20 }),
      ],
      spacing: { after: 120 },
    }),
    ...codeBlock(card.query),
    new Paragraph({ spacing: { after: 160 } }),
  );

  // 9. True Positive Criteria
  sections.push(heading3('True Positive Criteria'));
  sections.push(new Paragraph({ children: [new TextRun({ text: 'Confirmed TP:', bold: true, size: 22 })] }));
  card.true_positive_criteria.confirmed.forEach(c => sections.push(bullet(c)));
  sections.push(new Paragraph({ children: [new TextRun({ text: 'Investigate Further:', bold: true, size: 22 })] }));
  card.true_positive_criteria.investigate.forEach(c => sections.push(bullet(c)));
  sections.push(new Paragraph({ children: [new TextRun({ text: 'Not a TP:', bold: true, size: 22 })] }));
  card.true_positive_criteria.not_tp.forEach(c => sections.push(bullet(c)));

  // 10. Escalation Path
  sections.push(heading3('Escalation Path'));
  card.escalation_path.forEach((step, i) => sections.push(bullet(`${i + 1}. ${step}`)));

  // Page break after each card (except last)
  sections.push(pageBreak());

  return sections;
}

function buildMitreSummary(cards: HuntCard[]): (Paragraph | Table)[] {
  return [
    heading1('MITRE Coverage Summary'),
    buildTable(
      ['Tactic', 'T-ID', 'Technique', 'Coverage', 'Priority', 'Hunt ID'],
      cards.map(c => [
        c.mitre_mapping.tactic,
        c.mitre_mapping.technique_id,
        c.mitre_mapping.technique_name,
        c.coverage_status,
        c.priority,
        c.hunt_id,
      ])
    ),
    pageBreak(),
  ];
}

function buildDataRequirements(cards: HuntCard[]): (Paragraph | Table)[] {
  // Deduplicate across all cards
  const seen = new Set<string>();
  const rows: string[][] = [];

  for (const card of cards) {
    for (const ls of card.log_sources) {
      const key = `${ls.log_source}|${ls.event_id}`;
      if (!seen.has(key)) {
        seen.add(key);
        const huntIds = cards
          .filter(c => c.log_sources.some(l => `${l.log_source}|${l.event_id}` === key))
          .map(c => c.hunt_id)
          .join(', ');
        rows.push([ls.log_source, ls.event_id, ls.platform, ls.must_enable, huntIds]);
      }
    }
  }

  return [
    heading1('Data Requirements Summary'),
    body('Consolidated log source requirements across all hunt cards. Enable all before deploying.'),
    new Paragraph({ spacing: { after: 160 } }),
    buildTable(
      ['Log Source', 'Event ID', 'Platform', 'Must-Enable Setting', 'Required By'],
      rows
    ),
    pageBreak(),
  ];
}

// ── Main export ────────────────────────────────────────────────────────────

export async function generateHuntReport(report: HuntReport): Promise<string> {
  // Resolve output path
  const desktop = path.join(os.homedir(), 'Desktop');
  const folder = path.join(desktop, 'Threat Hunting Reports');
  if (!fs.existsSync(folder)) {
    fs.mkdirSync(folder, { recursive: true });
  }

  const safeActor = report.actor.replace(/[^a-zA-Z0-9_-]/g, '_');
  const filename = `${safeActor}_${report.date}.docx`;
  const outputPath = path.join(folder, filename);

  // Build document sections
  const children: (Paragraph | Table)[] = [
    ...buildCoverPage(report),
    ...buildExecutiveSummary(report),
  ];

  for (let i = 0; i < report.cards.length; i++) {
    children.push(...buildHuntCard(report.cards[i], i));
  }

  children.push(
    ...buildMitreSummary(report.cards),
    ...buildDataRequirements(report.cards),
  );

  // Appendix — full query listings
  children.push(heading1('Appendix — Full Query Listings'));
  for (const card of report.cards) {
    children.push(
      heading3(`${card.hunt_id} — ${card.mitre_mapping.technique_id}`),
      ...codeBlock(card.query),
      new Paragraph({ spacing: { after: 200 } }),
    );
  }

  const doc = new Document({
    creator: report.analyst,
    title: report.title,
    description: `Threat Hunt Report for ${report.actor}`,
    sections: [{ children }],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);

  return outputPath;
}
