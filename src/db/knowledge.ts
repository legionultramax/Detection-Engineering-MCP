// Knowledge Graph Database Schema
// For tribal knowledge: decisions, learnings, entities, relations
import { getDb, runQuery, runStatement } from './connection.js';

export function initKnowledgeSchema(): void {
  const db = getDb();
  
  db.exec(`
    -- Entities in the knowledge graph
    CREATE TABLE IF NOT EXISTS kg_entities (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      properties TEXT,
      reasoning TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_kg_entities_type ON kg_entities(type);
    CREATE INDEX IF NOT EXISTS idx_kg_entities_name ON kg_entities(name);
    
    -- Relations between entities
    CREATE TABLE IF NOT EXISTS kg_relations (
      id TEXT PRIMARY KEY,
      source_id TEXT NOT NULL,
      target_id TEXT NOT NULL,
      relation_type TEXT NOT NULL,
      description TEXT,
      reasoning TEXT,
      confidence REAL DEFAULT 1.0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (source_id) REFERENCES kg_entities(id),
      FOREIGN KEY (target_id) REFERENCES kg_entities(id)
    );
    
    CREATE INDEX IF NOT EXISTS idx_kg_relations_source ON kg_relations(source_id);
    CREATE INDEX IF NOT EXISTS idx_kg_relations_target ON kg_relations(target_id);
    CREATE INDEX IF NOT EXISTS idx_kg_relations_type ON kg_relations(relation_type);
    
    -- Decisions log (tribal knowledge)
    CREATE TABLE IF NOT EXISTS kg_decisions (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      context TEXT,
      decision TEXT NOT NULL,
      reasoning TEXT NOT NULL,
      alternatives TEXT,
      outcome TEXT,
      tags TEXT,
      entity_ids TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Learnings log
    CREATE TABLE IF NOT EXISTS kg_learnings (
      id TEXT PRIMARY KEY,
      topic TEXT NOT NULL,
      insight TEXT NOT NULL,
      source TEXT,
      confidence REAL DEFAULT 1.0,
      tags TEXT,
      related_decisions TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  console.error('[db] Knowledge graph schema initialized');
}

// Entity CRUD operations
export interface KGEntity {
  id: string;
  type: string;
  name: string;
  description?: string;
  properties?: Record<string, unknown>;
  reasoning?: string;
  created_at?: string;
  updated_at?: string;
}

export function createEntity(entity: Omit<KGEntity, 'id' | 'created_at' | 'updated_at'>): KGEntity {
  const id = `entity_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  runStatement(
    `INSERT INTO kg_entities (id, type, name, description, properties, reasoning)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [id, entity.type, entity.name, entity.description || null, 
     entity.properties ? JSON.stringify(entity.properties) : null, entity.reasoning || null]
  );
  return { id, ...entity };
}

export function getEntity(id: string): KGEntity | null {
  const results = runQuery<KGEntity>('SELECT * FROM kg_entities WHERE id = ?', [id]);
  return results[0] || null;
}

export function searchEntities(query: string, type?: string): KGEntity[] {
  let sql = 'SELECT * FROM kg_entities WHERE (name LIKE ? OR description LIKE ?)';
  const params: unknown[] = [`%${query}%`, `%${query}%`];
  
  if (type) {
    sql += ' AND type = ?';
    params.push(type);
  }
  
  return runQuery<KGEntity>(sql, params);
}

// Relation operations
export interface KGRelation {
  id: string;
  source_id: string;
  target_id: string;
  relation_type: string;
  description?: string;
  reasoning?: string;
  confidence?: number;
  created_at?: string;
}

export function createRelation(relation: Omit<KGRelation, 'id' | 'created_at'>): KGRelation {
  const id = `rel_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  runStatement(
    `INSERT INTO kg_relations (id, source_id, target_id, relation_type, description, reasoning, confidence)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, relation.source_id, relation.target_id, relation.relation_type,
     relation.description || null, relation.reasoning || null, relation.confidence || 1.0]
  );
  return { id, ...relation };
}

export function getRelationsForEntity(entityId: string): KGRelation[] {
  return runQuery<KGRelation>(
    'SELECT * FROM kg_relations WHERE source_id = ? OR target_id = ?',
    [entityId, entityId]
  );
}

// Decision logging
export interface Decision {
  id: string;
  title: string;
  context?: string;
  decision: string;
  reasoning: string;
  alternatives?: string[];
  outcome?: string;
  tags?: string[];
  entity_ids?: string[];
  created_at?: string;
}

export function logDecision(decision: Omit<Decision, 'id' | 'created_at'>): Decision {
  const id = `decision_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  runStatement(
    `INSERT INTO kg_decisions (id, title, context, decision, reasoning, alternatives, outcome, tags, entity_ids)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, decision.title, decision.context || null, decision.decision, decision.reasoning,
     decision.alternatives ? JSON.stringify(decision.alternatives) : null,
     decision.outcome || null,
     decision.tags ? JSON.stringify(decision.tags) : null,
     decision.entity_ids ? JSON.stringify(decision.entity_ids) : null]
  );
  return { id, ...decision };
}

export function getDecisions(limit: number = 50): Decision[] {
  return runQuery<Decision>(
    'SELECT * FROM kg_decisions ORDER BY created_at DESC LIMIT ?',
    [limit]
  );
}

export function searchDecisions(query: string): Decision[] {
  return runQuery<Decision>(
    `SELECT * FROM kg_decisions 
     WHERE title LIKE ? OR context LIKE ? OR decision LIKE ? OR reasoning LIKE ?
     ORDER BY created_at DESC`,
    [`%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`]
  );
}

// Learning operations
export interface Learning {
  id: string;
  topic: string;
  insight: string;
  source?: string;
  confidence?: number;
  tags?: string[];
  related_decisions?: string[];
  created_at?: string;
}

export function addLearning(learning: Omit<Learning, 'id' | 'created_at'>): Learning {
  const id = `learning_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  runStatement(
    `INSERT INTO kg_learnings (id, topic, insight, source, confidence, tags, related_decisions)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, learning.topic, learning.insight, learning.source || null, learning.confidence || 1.0,
     learning.tags ? JSON.stringify(learning.tags) : null,
     learning.related_decisions ? JSON.stringify(learning.related_decisions) : null]
  );
  return { id, ...learning };
}

export function getLearnings(topic?: string, limit: number = 50): Learning[] {
  let sql = 'SELECT * FROM kg_learnings';
  const params: unknown[] = [];
  
  if (topic) {
    sql += ' WHERE topic LIKE ?';
    params.push(`%${topic}%`);
  }
  
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);
  
  return runQuery<Learning>(sql, params);
}
