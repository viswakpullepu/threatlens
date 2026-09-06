import pg from 'pg';
const { Pool } = pg;

export function getDbUrl() {
  return process.env.DATABASE_URL || 
         process.env.POSTGRES_URL || 
         process.env.POSTGRES_PRISMA_URL || 
         process.env.POSTGRES_URL_NON_POOLING || '';
}

let pool = null;
let isInitialized = false;
let initPromise = null;

export function isPostgresConfigured() {
  return !!(getDbUrl() || process.env.PGHOST);
}

export function getPool() {
  if (pool) return pool;
  if (!isPostgresConfigured()) return null;

  try {
    const dbUrl = getDbUrl();
    const config = {};
    if (dbUrl) {
      config.connectionString = dbUrl;
      // Enable SSL if cloud database or explicitly required
      if (dbUrl.includes('sslmode=require') || 
          dbUrl.includes('supabase.co') || 
          dbUrl.includes('neon.tech') || 
          dbUrl.includes('render.com') || 
          dbUrl.includes('railway.app') || 
          dbUrl.includes('vercel-storage.com') ||
          dbUrl.includes('amazonaws.com')) {
        config.ssl = { rejectUnauthorized: false };
      }
    } else {
      config.host = process.env.PGHOST;
      config.port = parseInt(process.env.PGPORT || '5432', 10);
      config.user = process.env.PGUSER;
      config.password = process.env.PGPASSWORD;
      config.database = process.env.PGDATABASE;
      if (process.env.PGSSL === 'true') {
        config.ssl = { rejectUnauthorized: false };
      }
    }

    config.max = 10;
    config.idleTimeoutMillis = 30000;
    config.connectionTimeoutMillis = 5000;

    pool = new Pool(config);

    pool.on('error', (err) => {
      console.error('[PostgreSQL Pool Error]:', err.message);
    });

    return pool;
  } catch (err) {
    console.error('[PostgreSQL Init Failed]:', err.message);
    return null;
  }
}

/**
 * Automatically creates/updates tables and indexes for multi-user isolation.
 */
export async function initDb() {
  if (isInitialized) return true;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const p = getPool();
    if (!p) return false;

    try {
      const client = await p.connect();
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS emails (
            id VARCHAR(255) PRIMARY KEY,
            owner_email VARCHAR(255),
            session_id VARCHAR(255),
            subject TEXT,
            sender_email TEXT,
            sender_name TEXT,
            recipient_email TEXT,
            timestamp TIMESTAMPTZ,
            threat_score INTEGER DEFAULT 0,
            threat_level VARCHAR(50) DEFAULT 'Safe',
            threat_type VARCHAR(100),
            origin_ip VARCHAR(100),
            origin_location JSONB,
            auth_spf VARCHAR(50),
            auth_dkim VARCHAR(50),
            auth_dmarc VARCHAR(50),
            data JSONB NOT NULL,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
          );

          -- Ensure columns exist for upgraded schemas
          ALTER TABLE emails ADD COLUMN IF NOT EXISTS owner_email VARCHAR(255);
          ALTER TABLE emails ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);

          CREATE INDEX IF NOT EXISTS idx_emails_owner ON emails(owner_email);
          CREATE INDEX IF NOT EXISTS idx_emails_session ON emails(session_id);
          CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at DESC);
          CREATE INDEX IF NOT EXISTS idx_emails_threat_score ON emails(threat_score DESC);

          CREATE TABLE IF NOT EXISTS oauth_sessions (
            id VARCHAR(255) PRIMARY KEY,
            user_email VARCHAR(255),
            tokens JSONB NOT NULL,
            user_profile JSONB,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
          );

          CREATE INDEX IF NOT EXISTS idx_oauth_user_email ON oauth_sessions(user_email);
        `);
        isInitialized = true;
        console.log('[PostgreSQL] Database schema with multi-user tenant isolation initialized.');
        return true;
      } finally {
        client.release();
      }
    } catch (err) {
      console.warn('[PostgreSQL Init Warning]: Failed to initialize tables:', err.message);
      return false;
    }
  })();

  return initPromise;
}

/**
 * Persists an analyzed email into PostgreSQL tagged with the owner/session.
 */
export async function saveEmailToDb(email, ownerEmail = null, sessionId = null) {
  const p = getPool();
  if (!p) return false;

  try {
    await initDb();
    const query = `
      INSERT INTO emails (
        id, owner_email, session_id,
        subject, sender_email, sender_name, recipient_email,
        timestamp, threat_score, threat_level, threat_type,
        origin_ip, origin_location, auth_spf, auth_dkim, auth_dmarc,
        data, created_at
      ) VALUES (
        $1, $2, $3,
        $4, $5, $6, $7,
        $8, $9, $10, $11,
        $12, $13, $14, $15, $16,
        $17, NOW()
      )
      ON CONFLICT (id) DO UPDATE SET
        owner_email = COALESCE(EXCLUDED.owner_email, emails.owner_email),
        session_id = COALESCE(EXCLUDED.session_id, emails.session_id),
        subject = EXCLUDED.subject,
        sender_email = EXCLUDED.sender_email,
        sender_name = EXCLUDED.sender_name,
        recipient_email = EXCLUDED.recipient_email,
        timestamp = EXCLUDED.timestamp,
        threat_score = EXCLUDED.threat_score,
        threat_level = EXCLUDED.threat_level,
        threat_type = EXCLUDED.threat_type,
        origin_ip = EXCLUDED.origin_ip,
        origin_location = EXCLUDED.origin_location,
        auth_spf = EXCLUDED.auth_spf,
        auth_dkim = EXCLUDED.auth_dkim,
        auth_dmarc = EXCLUDED.auth_dmarc,
        data = EXCLUDED.data;
    `;

    const authSpf = email.authentication?.spf?.status || null;
    const authDkim = email.authentication?.dkim?.status || null;
    const authDmarc = email.authentication?.dmarc?.status || null;

    const values = [
      email.id,
      ownerEmail || email.ownerEmail || null,
      sessionId || email.sessionId || null,
      email.subject || '(No Subject)',
      email.sender?.email || '',
      email.sender?.name || '',
      email.recipient || '',
      email.timestamp ? new Date(email.timestamp) : new Date(),
      typeof email.threatScore === 'number' ? email.threatScore : 0,
      email.threatLevel || 'Safe',
      email.threatType || 'Clean Delivery',
      email.originLocation?.ip || null,
      email.originLocation ? JSON.stringify(email.originLocation) : null,
      authSpf,
      authDkim,
      authDmarc,
      JSON.stringify(email)
    ];

    await p.query(query, values);
    return true;
  } catch (err) {
    console.error('[PostgreSQL saveEmail Error]:', err.message);
    return false;
  }
}

/**
 * Retrieves analyzed emails strictly for the authenticated user/session.
 */
export async function getEmailsFromDb(ownerEmail = null, sessionId = null, limit = 1000) {
  const p = getPool();
  if (!p) return null;

  try {
    await initDb();
    let query = '';
    let values = [];

    if (ownerEmail && sessionId) {
      query = `SELECT data FROM emails WHERE owner_email = $1 OR session_id = $2 ORDER BY created_at DESC LIMIT $3`;
      values = [ownerEmail.toLowerCase().trim(), sessionId, limit];
    } else if (ownerEmail) {
      query = `SELECT data FROM emails WHERE owner_email = $1 ORDER BY created_at DESC LIMIT $2`;
      values = [ownerEmail.toLowerCase().trim(), limit];
    } else if (sessionId) {
      query = `SELECT data FROM emails WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2`;
      values = [sessionId, limit];
    } else {
      // Return empty array for unauthenticated/unscoped requests to prevent data leaks
      return [];
    }

    const result = await p.query(query, values);
    return result.rows.map(row => {
      const parsed = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
      return parsed;
    });
  } catch (err) {
    console.error('[PostgreSQL getEmails Error]:', err.message);
    return null;
  }
}

/**
 * Saves or updates OAuth tokens and user profile keyed by sessionId and userEmail.
 */
export async function saveOAuthToDb(tokens, userProfile, sessionId = 'primary_user') {
  const p = getPool();
  if (!p) return false;

  try {
    await initDb();
    const query = `
      INSERT INTO oauth_sessions (id, user_email, tokens, user_profile, updated_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (id) DO UPDATE SET
        user_email = EXCLUDED.user_email,
        tokens = EXCLUDED.tokens,
        user_profile = EXCLUDED.user_profile,
        updated_at = NOW();
    `;
    const userEmail = userProfile?.email ? userProfile.email.toLowerCase().trim() : null;
    await p.query(query, [
      sessionId,
      userEmail,
      JSON.stringify(tokens),
      userProfile ? JSON.stringify(userProfile) : null
    ]);
    return true;
  } catch (err) {
    console.error('[PostgreSQL saveOAuth Error]:', err.message);
    return false;
  }
}

/**
 * Retrieves OAuth session state strictly by sessionId (or userEmail fallback).
 */
export async function getOAuthFromDb(sessionId = 'primary_user') {
  const p = getPool();
  if (!p) return null;

  try {
    await initDb();
    const result = await p.query(`
      SELECT tokens, user_profile, updated_at 
      FROM oauth_sessions 
      WHERE id = $1 OR user_email = $1
      ORDER BY updated_at DESC
      LIMIT 1
    `, [sessionId]);

    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    return {
      tokens: typeof row.tokens === 'string' ? JSON.parse(row.tokens) : row.tokens,
      user: typeof row.user_profile === 'string' ? JSON.parse(row.user_profile) : row.user_profile,
      updatedAt: row.updated_at
    };
  } catch (err) {
    console.error('[PostgreSQL getOAuth Error]:', err.message);
    return null;
  }
}

/**
 * Clears OAuth session state strictly for sessionId.
 */
export async function clearOAuthFromDb(sessionId = 'primary_user') {
  const p = getPool();
  if (!p) return false;

  try {
    await initDb();
    await p.query('DELETE FROM oauth_sessions WHERE id = $1 OR user_email = $1', [sessionId]);
    return true;
  } catch (err) {
    console.error('[PostgreSQL clearOAuth Error]:', err.message);
    return false;
  }
}

/**
 * Checks PostgreSQL health and counts stored records.
 */
export async function getDbHealth() {
  const configured = isPostgresConfigured();
  if (!configured) {
    return {
      connected: false,
      configured: false,
      provider: 'local_file_memory',
      message: 'PostgreSQL not configured (DATABASE_URL not set). Operating in local storage mode.'
    };
  }

  const p = getPool();
  if (!p) {
    return {
      connected: false,
      configured: true,
      provider: 'postgresql',
      error: 'Failed to create PostgreSQL client pool'
    };
  }

  try {
    const start = Date.now();
    const client = await p.connect();
    try {
      const emailCountRes = await client.query('SELECT COUNT(*) as count FROM emails');
      const oauthCountRes = await client.query('SELECT COUNT(*) as count FROM oauth_sessions');
      const latencyMs = Date.now() - start;

      return {
        connected: true,
        configured: true,
        provider: 'postgresql',
        latencyMs,
        tables: {
          emails: parseInt(emailCountRes.rows[0].count, 10),
          oauthSessions: parseInt(oauthCountRes.rows[0].count, 10)
        }
      };
    } finally {
      client.release();
    }
  } catch (err) {
    return {
      connected: false,
      configured: true,
      provider: 'postgresql',
      error: err.message
    };
  }
}
