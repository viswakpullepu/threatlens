import pg from 'pg';
const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL || 
                     process.env.POSTGRES_URL || 
                     process.env.POSTGRES_PRISMA_URL || 
                     process.env.POSTGRES_URL_NON_POOLING || '';

let pool = null;
let isInitialized = false;
let initPromise = null;

export function isPostgresConfigured() {
  return !!(DATABASE_URL || process.env.PGHOST);
}

export function getPool() {
  if (pool) return pool;
  if (!isPostgresConfigured()) return null;

  try {
    const config = {};
    if (DATABASE_URL) {
      config.connectionString = DATABASE_URL;
      // Enable SSL if cloud database or explicitly required
      if (DATABASE_URL.includes('sslmode=require') || 
          DATABASE_URL.includes('supabase.co') || 
          DATABASE_URL.includes('neon.tech') || 
          DATABASE_URL.includes('render.com') || 
          DATABASE_URL.includes('railway.app') || 
          DATABASE_URL.includes('vercel-storage.com') ||
          DATABASE_URL.includes('amazonaws.com')) {
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
 * Automatically creates tables and indexes if they do not already exist.
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

          CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at DESC);
          CREATE INDEX IF NOT EXISTS idx_emails_threat_score ON emails(threat_score DESC);

          CREATE TABLE IF NOT EXISTS oauth_sessions (
            id VARCHAR(255) PRIMARY KEY,
            user_email VARCHAR(255),
            tokens JSONB NOT NULL,
            user_profile JSONB,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
          );
        `);
        isInitialized = true;
        console.log('[PostgreSQL] Database schema verified and initialized successfully.');
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
 * Persists an analyzed email into PostgreSQL.
 */
export async function saveEmailToDb(email) {
  const p = getPool();
  if (!p) return false;

  try {
    await initDb();
    const query = `
      INSERT INTO emails (
        id, subject, sender_email, sender_name, recipient_email,
        timestamp, threat_score, threat_level, threat_type,
        origin_ip, origin_location, auth_spf, auth_dkim, auth_dmarc,
        data, created_at
      ) VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9,
        $10, $11, $12, $13, $14,
        $15, NOW()
      )
      ON CONFLICT (id) DO UPDATE SET
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
 * Retrieves analyzed emails ordered by most recent first.
 */
export async function getEmailsFromDb(limit = 100) {
  const p = getPool();
  if (!p) return null;

  try {
    await initDb();
    const result = await p.query(`
      SELECT data FROM emails 
      ORDER BY created_at DESC 
      LIMIT $1
    `, [limit]);

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
 * Saves or updates OAuth tokens and user profile in PostgreSQL.
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
    const userEmail = userProfile?.email || null;
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
 * Retrieves OAuth session state from PostgreSQL.
 */
export async function getOAuthFromDb(sessionId = 'primary_user') {
  const p = getPool();
  if (!p) return null;

  try {
    await initDb();
    const result = await p.query(`
      SELECT tokens, user_profile, updated_at 
      FROM oauth_sessions 
      WHERE id = $1
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
 * Clears OAuth session state upon logout / disconnect.
 */
export async function clearOAuthFromDb(sessionId = 'primary_user') {
  const p = getPool();
  if (!p) return false;

  try {
    await initDb();
    await p.query('DELETE FROM oauth_sessions WHERE id = $1', [sessionId]);
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
