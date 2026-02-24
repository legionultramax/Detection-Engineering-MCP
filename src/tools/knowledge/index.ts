// Knowledge Graph Tools - Tribal knowledge capture and retrieval
import { defineTool, ToolDefinition } from '../registry.js';
import {
  createEntity, getEntity, searchEntities,
  createRelation, getRelationsForEntity,
  logDecision, getDecisions, searchDecisions,
  addLearning, getLearnings,
  KGEntity, KGRelation, Decision, Learning,
} from '../../db/knowledge.js';

// Create a knowledge entity
const createEntityTool = defineTool({
  name: 'create_entity',
  description: 'Create an entity in the knowledge graph (e.g., technique, actor, tool, detection)',
  inputSchema: {
    type: 'object',
    properties: {
      type: { type: 'string', description: 'Entity type: technique, actor, tool, detection, vulnerability, campaign' },
      name: { type: 'string', description: 'Entity name' },
      description: { type: 'string', description: 'Description of the entity' },
      properties: { type: 'object', description: 'Additional properties as key-value pairs' },
      reasoning: { type: 'string', description: 'Why this entity is being created/tracked' },
    },
    required: ['type', 'name'],
  },
  handler: async (args) => {
    const { type, name, description, properties, reasoning } = args as {
      type: string; name: string; description?: string; 
      properties?: Record<string, unknown>; reasoning?: string;
    };
    
    const entity = createEntity({ type, name, description, properties, reasoning });
    return {
      success: true,
      entity: {
        id: entity.id,
        type: entity.type,
        name: entity.name,
        description: entity.description,
      },
    };
  },
});

// Search entities
const searchEntitiesTool = defineTool({
  name: 'search_entities',
  description: 'Search knowledge graph entities by name or description',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search query' },
      type: { type: 'string', description: 'Optional: filter by entity type' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, type } = args as { query: string; type?: string };
    const entities = searchEntities(query, type);
    
    return {
      count: entities.length,
      entities: entities.map(e => ({
        id: e.id,
        type: e.type,
        name: e.name,
        description: e.description?.substring(0, 100),
      })),
    };
  },
});

// Create a relation between entities
const createRelationTool = defineTool({
  name: 'create_relation',
  description: 'Create a relation between two entities in the knowledge graph',
  inputSchema: {
    type: 'object',
    properties: {
      source_id: { type: 'string', description: 'Source entity ID' },
      target_id: { type: 'string', description: 'Target entity ID' },
      relation_type: { type: 'string', description: 'Relation type: uses, detects, mitigates, targets, exploits, etc.' },
      description: { type: 'string', description: 'Description of the relation' },
      reasoning: { type: 'string', description: 'Why this relation exists' },
      confidence: { type: 'number', description: 'Confidence score 0-1 (default: 1.0)' },
    },
    required: ['source_id', 'target_id', 'relation_type'],
  },
  handler: async (args) => {
    const { source_id, target_id, relation_type, description, reasoning, confidence } = args as {
      source_id: string; target_id: string; relation_type: string;
      description?: string; reasoning?: string; confidence?: number;
    };
    
    // Verify entities exist
    const source = getEntity(source_id);
    const target = getEntity(target_id);
    
    if (!source) return { error: `Source entity not found: ${source_id}` };
    if (!target) return { error: `Target entity not found: ${target_id}` };
    
    const relation = createRelation({
      source_id, target_id, relation_type, description, reasoning, confidence
    });
    
    return {
      success: true,
      relation: {
        id: relation.id,
        source: source.name,
        target: target.name,
        type: relation.relation_type,
      },
    };
  },
});

// Log a decision (tribal knowledge)
const logDecisionTool = defineTool({
  name: 'log_decision',
  description: 'Log an analytical decision with reasoning for tribal knowledge capture',
  inputSchema: {
    type: 'object',
    properties: {
      title: { type: 'string', description: 'Short title for the decision' },
      context: { type: 'string', description: 'Context or situation leading to the decision' },
      decision: { type: 'string', description: 'The decision made' },
      reasoning: { type: 'string', description: 'Why this decision was made' },
      alternatives: { type: 'array', items: { type: 'string' }, description: 'Alternative approaches considered' },
      tags: { type: 'array', items: { type: 'string' }, description: 'Tags for categorization' },
    },
    required: ['title', 'decision', 'reasoning'],
  },
  handler: async (args) => {
    const { title, context, decision, reasoning, alternatives, tags } = args as {
      title: string; context?: string; decision: string; reasoning: string;
      alternatives?: string[]; tags?: string[];
    };
    
    const logged = logDecision({ title, context, decision, reasoning, alternatives, tags });
    
    return {
      success: true,
      decision: {
        id: logged.id,
        title: logged.title,
        created: new Date().toISOString(),
      },
    };
  },
});

// Get recent decisions
const getDecisionsTool = defineTool({
  name: 'get_decisions',
  description: 'Get recent logged decisions (tribal knowledge)',
  inputSchema: {
    type: 'object',
    properties: {
      limit: { type: 'number', description: 'Maximum decisions to return (default: 20)' },
      search: { type: 'string', description: 'Optional search term' },
    },
  },
  handler: async (args) => {
    const { limit = 20, search } = args as { limit?: number; search?: string };
    
    const decisions = search ? searchDecisions(search) : getDecisions(limit);
    
    return {
      count: decisions.length,
      decisions: decisions.slice(0, limit).map(d => ({
        id: d.id,
        title: d.title,
        decision: d.decision,
        reasoning: d.reasoning?.substring(0, 200),
        created: d.created_at,
      })),
    };
  },
});

// Add a learning
const addLearningTool = defineTool({
  name: 'add_learning',
  description: 'Add a learning or insight gained during analysis',
  inputSchema: {
    type: 'object',
    properties: {
      topic: { type: 'string', description: 'Topic area (e.g., "ransomware", "powershell", "lateral movement")' },
      insight: { type: 'string', description: 'The insight or learning' },
      source: { type: 'string', description: 'Source of the learning' },
      confidence: { type: 'number', description: 'Confidence in this learning 0-1' },
      tags: { type: 'array', items: { type: 'string' }, description: 'Tags for categorization' },
    },
    required: ['topic', 'insight'],
  },
  handler: async (args) => {
    const { topic, insight, source, confidence, tags } = args as {
      topic: string; insight: string; source?: string; confidence?: number; tags?: string[];
    };
    
    const learning = addLearning({ topic, insight, source, confidence, tags });
    
    return {
      success: true,
      learning: {
        id: learning.id,
        topic: learning.topic,
      },
    };
  },
});

// Get learnings
const getLearningsTool = defineTool({
  name: 'get_learnings',
  description: 'Get learnings/insights by topic',
  inputSchema: {
    type: 'object',
    properties: {
      topic: { type: 'string', description: 'Filter by topic' },
      limit: { type: 'number', description: 'Maximum results (default: 20)' },
    },
  },
  handler: async (args) => {
    const { topic, limit = 20 } = args as { topic?: string; limit?: number };
    
    const learnings = getLearnings(topic, limit);
    
    return {
      count: learnings.length,
      learnings: learnings.map(l => ({
        id: l.id,
        topic: l.topic,
        insight: l.insight,
        source: l.source,
        confidence: l.confidence,
        created: l.created_at,
      })),
    };
  },
});

// Get knowledge summary
const getKnowledgeSummary = defineTool({
  name: 'get_knowledge_summary',
  description: 'Get a summary of the knowledge graph contents',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    const decisions = getDecisions(100);
    const learnings = getLearnings(undefined, 100);
    const entities = searchEntities('', undefined);
    
    // Group by type
    const entityTypes: Record<string, number> = {};
    for (const e of entities) {
      entityTypes[e.type] = (entityTypes[e.type] || 0) + 1;
    }
    
    const learningTopics: Record<string, number> = {};
    for (const l of learnings) {
      learningTopics[l.topic] = (learningTopics[l.topic] || 0) + 1;
    }
    
    return {
      total_decisions: decisions.length,
      total_learnings: learnings.length,
      total_entities: entities.length,
      entities_by_type: entityTypes,
      learnings_by_topic: learningTopics,
      recent_decisions: decisions.slice(0, 5).map(d => d.title),
    };
  },
});

export const knowledgeTools: ToolDefinition[] = [
  createEntityTool,
  searchEntitiesTool,
  createRelationTool,
  logDecisionTool,
  getDecisionsTool,
  addLearningTool,
  getLearningsTool,
  getKnowledgeSummary,
];

export const knowledgeToolCount = knowledgeTools.length;
