// MCP Prompts Handler
// Predefined prompts for common security analysis workflows

interface Prompt {
  name: string;
  description: string;
  arguments?: Array<{
    name: string;
    description: string;
    required?: boolean;
  }>;
}

const prompts: Prompt[] = [
  {
    name: 'analyze-technique',
    description: 'Analyze a MITRE ATT&CK technique and find related detections',
    arguments: [
      { name: 'technique_id', description: 'MITRE technique ID (e.g., T1059)', required: true },
    ],
  },
  {
    name: 'threat-hunt',
    description: 'Generate a threat hunting plan for a specific threat profile',
    arguments: [
      { name: 'profile', description: 'Threat profile: ransomware, apt, insider, etc.', required: true },
    ],
  },
  {
    name: 'coverage-report',
    description: 'Generate a detection coverage report',
    arguments: [
      { name: 'focus', description: 'Focus area: all, initial-access, persistence, etc.' },
    ],
  },
  {
    name: 'investigate-ioc',
    description: 'Investigate an indicator of compromise',
    arguments: [
      { name: 'ioc', description: 'The IOC to investigate (hash, IP, domain, etc.)', required: true },
    ],
  },
  {
    name: 'detection-review',
    description: 'Review and analyze a specific detection rule',
    arguments: [
      { name: 'detection_id', description: 'Detection ID to review', required: true },
    ],
  },
  {
    name: 'yara-to-sigma',
    description: 'Convert a YARA rule to an approximate Sigma rule',
    arguments: [
      { name: 'yara_rule', description: 'The full YARA rule text to convert', required: true },
      { name: 'logsource_category', description: 'Sigma logsource category (default: process_creation)' },
      { name: 'product', description: 'Target product (default: windows)' },
      { name: 'title_override', description: 'Custom title for the generated Sigma rule' },
    ],
  },
];

export function listPrompts() {
  return { prompts };
}

export function getPrompt(name: string, args: Record<string, string>) {
  const prompt = prompts.find(p => p.name === name);
  
  if (!prompt) {
    throw new Error(`Unknown prompt: ${name}`);
  }
  
  let messages: Array<{ role: string; content: { type: string; text: string } }> = [];
  
  switch (name) {
    case 'analyze-technique': {
      const techniqueId = args.technique_id || 'T1059';
      messages = [{
        role: 'user',
        content: {
          type: 'text',
          text: `Analyze MITRE ATT&CK technique ${techniqueId}:

1. First, look up the technique details using lookup_mitre_technique
2. Search for all detections mapped to this technique using list_by_mitre
3. Check if any LOLBAS binaries are associated with this technique
4. Provide a summary including:
   - Technique overview
   - Detection coverage (number of detections by source)
   - Coverage gaps or recommendations
   - Related techniques to consider`,
        },
      }];
      break;
    }
    
    case 'threat-hunt': {
      const profile = args.profile || 'ransomware';
      messages = [{
        role: 'user',
        content: {
          type: 'text',
          text: `Create a threat hunting plan for ${profile} threats:

1. Get the threat profile using get_threat_profile
2. For each key technique, check detection coverage using identify_gaps
3. Search for relevant detections using search_detections
4. Log your hunting hypothesis as a decision using log_decision

Provide a hunting plan that includes:
- Key indicators to search for
- Relevant detection rules to leverage
- Data sources needed
- Hunting queries or search strategies`,
        },
      }];
      break;
    }
    
    case 'coverage-report': {
      const focus = args.focus || 'all';
      messages = [{
        role: 'user',
        content: {
          type: 'text',
          text: `Generate a detection coverage report${focus !== 'all' ? ` focused on ${focus}` : ''}:

1. Get overall statistics using get_stats
2. Analyze MITRE coverage using analyze_coverage
3. Identify gaps for key threat profiles using identify_gaps
4. Summarize findings

Report should include:
- Total detection count by source
- MITRE tactic coverage percentages
- Top covered techniques
- Critical gaps that need attention
- Recommendations for improvement`,
        },
      }];
      break;
    }
    
    case 'investigate-ioc': {
      const ioc = args.ioc || '';
      messages = [{
        role: 'user',
        content: {
          type: 'text',
          text: `Investigate this indicator of compromise: ${ioc}

1. First, analyze the IOC type using analyze_ioc
2. Search for related detections that might trigger on this IOC
3. Check if it's associated with any known campaigns or malware
4. Log your analysis as a decision for future reference

Provide:
- IOC classification and type
- Relevant lookup sources
- Related detections
- Recommended response actions`,
        },
      }];
      break;
    }
    
    case 'detection-review': {
      const detectionId = args.detection_id || '';
      messages = [{
        role: 'user',
        content: {
          type: 'text',
          text: `Review detection rule: ${detectionId}

1. Get the full detection details using get_detection
2. Look up the associated MITRE techniques
3. Search for similar detections from other sources
4. Analyze the detection quality

Review should cover:
- Detection purpose and coverage
- MITRE mapping accuracy
- Potential false positives
- Suggestions for improvement
- Similar detections from other sources`,
        },
      }];
      break;
    }
    
    case 'yara-to-sigma': {
      const yaraRule = args.yara_rule || '';
      const logsourceCategory = args.logsource_category || 'process_creation';
      const product = args.product || 'windows';
      const titleOverride = args.title_override || '';
      messages = [{
        role: 'user',
        content: {
          type: 'text',
          text: `Convert this YARA rule to a Sigma detection rule:

\`\`\`yara
${yaraRule}
\`\`\`

Parameters:
- Logsource category: ${logsourceCategory}
- Product: ${product}
${titleOverride ? `- Custom title: ${titleOverride}` : ''}

Use the convert_yara_to_sigma tool with these parameters.

After conversion:
1. Review the generated Sigma rule
2. Explain any conversion limitations
3. Suggest improvements for the detection logic
4. Note what manual tuning may be needed`,
        },
      }];
      break;
    }
    
    default:
      messages = [{
        role: 'user',
        content: {
          type: 'text',
          text: `Run the ${name} workflow`,
        },
      }];
  }
  
  return {
    description: prompt.description,
    messages,
  };
}
