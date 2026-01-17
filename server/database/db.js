import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, writeFileSync, existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dbPath = join(__dirname, '../../auth.json');

// Simple in-memory database with persistence
class SimpleDB {
  constructor() {
    this.data = {
      users: [],
      credentials: [],
      known_devices: [],
      sessions: [], // 🔒 Session tracking table
      otps: [],
      fallback_usage: [],
      audit_logs: [],
      risk_events: []
    };
    this.autoIncrement = {
      users: 1,
      known_devices: 1,
      sessions: 1,
      otps: 1,
      fallback_usage: 1,
      audit_logs: 1,
      risk_events: 1
    };
    this.load();
  }

  load() {
    if (existsSync(dbPath)) {
      try {
        const content = readFileSync(dbPath, 'utf8');
        const loaded = JSON.parse(content);
        this.data = loaded.data || this.data;
        this.autoIncrement = loaded.autoIncrement || this.autoIncrement;
        console.log('📂 Database loaded from file');
      } catch (error) {
        console.warn('⚠️  Could not load database, starting fresh');
      }
    } else {
      console.log('🆕 Creating new database');
    }
  }

  save() {
    try {
      const content = JSON.stringify({ data: this.data, autoIncrement: this.autoIncrement }, null, 2);
      writeFileSync(dbPath, content, { flag: 'w' });
    } catch (error) {
      console.error('Failed to save database:', error);
    }
  }

  prepare(sql) {
    return {
      run: (...params) => this.run(sql, params),
      get: (...params) => this.get(sql, params),
      all: (...params) => this.all(sql, params)
    };
  }

  run(sql, params = []) {
    const insertMatch = sql.match(/INSERT INTO (\w+)/i);
    const updateMatch = sql.match(/UPDATE (\w+)/i);
    const deleteMatch = sql.match(/DELETE FROM (\w+)/i);

    if (insertMatch) {
      const table = insertMatch[1];
      const row = this.parseInsert(sql, params);
      
      if (this.autoIncrement[table] !== undefined && !row.id) {
        row.id = this.autoIncrement[table]++;
      }
      
      this.data[table].push(row);
      this.save();
      return { changes: 1, lastInsertRowid: row.id };
    } else if (updateMatch) {
      const table = updateMatch[1];
      const result = this.parseUpdate(sql, params, table);
      this.save();
      return { changes: result };
    } else if (deleteMatch) {
      const table = deleteMatch[1];
      const result = this.parseDelete(sql, params, table);
      this.save();
      return { changes: result };
    }

    return { changes: 0 };
  }

  get(sql, params = []) {
    const selectMatch = sql.match(/SELECT .+ FROM (\w+)/i);
    if (!selectMatch) return null;

    const table = selectMatch[1];
    const where = this.parseWhere(sql, params);
    const orderBy = this.parseOrderBy(sql);
    
    let results = this.data[table] || [];
    results = this.filterResults(results, where);
    
    if (orderBy) {
      results = this.sortResults(results, orderBy);
    }

    return results[0] || null;
  }

  all(sql, params = []) {
    const selectMatch = sql.match(/SELECT .+ FROM (\w+)/i);
    if (!selectMatch) return [];

    const table = selectMatch[1];
    const where = this.parseWhere(sql, params);
    const orderBy = this.parseOrderBy(sql);
    const limit = this.parseLimit(sql, params);
    
    let results = this.data[table] || [];
    results = this.filterResults(results, where);
    
    if (orderBy) {
      results = this.sortResults(results, orderBy);
    }

    if (limit) {
      results = results.slice(0, limit);
    }

    return results;
  }

  parseInsert(sql, params) {
    const row = {};
    const valuesMatch = sql.match(/VALUES\s*\((.*?)\)/i);
    const columnsMatch = sql.match(/\((.*?)\)\s*VALUES/i);
    
    if (columnsMatch && valuesMatch) {
      const columns = columnsMatch[1].split(',').map(c => c.trim());
      columns.forEach((col, i) => {
        row[col] = params[i];
      });
    }

    // Add timestamps
    if (!row.created_at && !row.timestamp) {
      row.created_at = new Date().toISOString();
    }
    if (!row.last_seen && sql.includes('known_devices')) {
      row.last_seen = new Date().toISOString();
    }

    return row;
  }

  parseUpdate(sql, params, table) {
    const where = this.parseWhere(sql, params.slice(-1));
    const setMatch = sql.match(/SET\s+(.+?)\s+WHERE/i);
    
    if (!setMatch) return 0;

    const updates = {};
    const setParts = setMatch[1].split(',');
    let paramIndex = 0;

    setParts.forEach(part => {
      const [col] = part.trim().split('=');
      updates[col.trim()] = params[paramIndex++];
    });

    let count = 0;
    this.data[table].forEach(row => {
      if (this.matchesWhere(row, where)) {
        Object.assign(row, updates);
        count++;
      }
    });

    return count;
  }

  parseDelete(sql, params, table) {
    const where = this.parseWhere(sql, params);
    const originalLength = this.data[table].length;
    this.data[table] = this.data[table].filter(row => !this.matchesWhere(row, where));
    return originalLength - this.data[table].length;
  }

  parseWhere(sql, params) {
    const whereMatch = sql.match(/WHERE\s+(.+?)(?:ORDER BY|LIMIT|$)/i);
    if (!whereMatch) return null;

    const conditions = whereMatch[1].split(/\s+AND\s+/i);
    const where = {};
    let paramIndex = 0;

    conditions.forEach(condition => {
      const match = condition.match(/(\w+)\s*(=|>|<|>=|<=|LIKE)\s*\?/i);
      if (match) {
        where[match[1]] = { op: match[2], value: params[paramIndex++] };
      }
    });

    return where;
  }

  parseOrderBy(sql) {
    const match = sql.match(/ORDER BY\s+(\w+)\s+(ASC|DESC)?/i);
    return match ? { column: match[1], direction: (match[2] || 'ASC').toUpperCase() } : null;
  }

  parseLimit(sql, params) {
    const match = sql.match(/LIMIT\s+\?/i);
    if (match) {
      return params[params.length - 1];
    }
    const directMatch = sql.match(/LIMIT\s+(\d+)/i);
    return directMatch ? parseInt(directMatch[1]) : null;
  }

  filterResults(results, where) {
    if (!where) return results;
    return results.filter(row => this.matchesWhere(row, where));
  }

  matchesWhere(row, where) {
    if (!where) return true;

    return Object.entries(where).every(([col, condition]) => {
      const rowValue = row[col];
      const { op, value } = condition;

      switch (op.toUpperCase()) {
        case '=': return rowValue == value;
        case '>': return rowValue > value;
        case '<': return rowValue < value;
        case '>=': return rowValue >= value;
        case '<=': return rowValue <= value;
        case 'LIKE': return String(rowValue).includes(value.replace(/%/g, ''));
        default: return true;
      }
    });
  }

  sortResults(results, orderBy) {
    return [...results].sort((a, b) => {
      const aVal = a[orderBy.column];
      const bVal = b[orderBy.column];
      const comparison = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      return orderBy.direction === 'DESC' ? -comparison : comparison;
    });
  }

  exec(sql) {
    // Handle CREATE TABLE and other DDL statements (no-op for JSON storage)
    return;
  }
}

const db = new SimpleDB();

// Save on exit only (no auto-save to prevent nodemon restart loop)
process.on('exit', () => db.save());
process.on('SIGINT', () => {
  db.save();
  process.exit();
});
process.on('SIGTERM', () => {
  db.save();
  process.exit();
});

// Initialize tables (no-op)
db.exec(`
  -- Users table
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Passkey credentials table
  CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL,
    transports TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Known devices table
  CREATE TABLE IF NOT EXISTS known_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_fingerprint TEXT NOT NULL,
    device_name TEXT,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    trust_level INTEGER DEFAULT 50,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, device_fingerprint)
  );

  -- OTP storage table
  CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp TEXT NOT NULL,
    purpose TEXT DEFAULT 'login',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0
  );

  -- Fallback usage tracking
  CREATE TABLE IF NOT EXISTS fallback_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Security audit logs
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT,
    event TEXT NOT NULL,
    details TEXT,
    risk_score INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    location TEXT,
    success INTEGER DEFAULT 1,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  -- Risk events table
  CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    factors TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Create indexes for performance
  CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
  CREATE INDEX IF NOT EXISTS idx_known_devices_user_id ON known_devices(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_otps_email ON otps(email);
  CREATE INDEX IF NOT EXISTS idx_fallback_usage_user_id ON fallback_usage(user_id);
`);

console.log('✅ Database initialized successfully');

export default db;
