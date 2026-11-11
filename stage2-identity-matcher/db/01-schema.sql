-- =============================================================================
-- CampusShield - Stage 2: database schema
--
-- Runs automatically the first time the PostgreSQL container starts.
-- Tables:
--   users               who can log in, and their role
--   verification_codes  one-time codes e-mailed during captive-portal login
--   sessions            which device (IP) belongs to which verified user, until when
--   timetable           class times; social media rules depend on these
--   domain_categories   domain -> category (moved here from the SNI extractor)
--   policies            what each role may do with each category, in and out of class
-- =============================================================================

-- ---------------------------------------------------------------------------
-- users: one row per person who has verified their university e-mail.
-- role decides which policy applies. 'guest' is used for anyone not verified,
-- and gets the most restrictive policy (fail-closed, as in the proposal).
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,                 -- one account per e-mail
    role        TEXT NOT NULL DEFAULT 'student'
                CHECK (role IN ('student', 'faculty', 'admin')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- verification_codes: the one-time code sent to the user's e-mail.
-- Only a HASH of the code is stored, so a database leak does not reveal codes.
-- expires_at and attempts limit guessing (e.g. 10 minutes, 5 attempts).
-- ---------------------------------------------------------------------------
CREATE TABLE verification_codes (
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_codes_email ON verification_codes (email);

-- ---------------------------------------------------------------------------
-- sessions: after a successful login, the device's IP is linked to the user
-- until expires_at, so the user does not log in again on every connection.
-- Only a HASH of the session token is stored, for the same reason as above.
-- The gateway looks up a client IP here to find the user's role.
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    client_ip   INET NOT NULL,                        -- INET = PostgreSQL's IP address type
    mac_address MACADDR,                              -- optional, extra device check
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);
-- Fast lookup "which active session does this IP have?"
CREATE INDEX idx_sessions_ip ON sessions (client_ip, expires_at);

-- ---------------------------------------------------------------------------
-- timetable: when classes run. day_of_week uses ISO numbering
-- (1 = Monday ... 7 = Sunday), the same as PostgreSQL's EXTRACT(ISODOW ...).
-- ---------------------------------------------------------------------------
CREATE TABLE timetable (
    id           SERIAL PRIMARY KEY,
    day_of_week  SMALLINT NOT NULL CHECK (day_of_week BETWEEN 1 AND 7),
    start_time   TIME NOT NULL,
    end_time     TIME NOT NULL,
    label        TEXT NOT NULL,                       -- e.g. 'BSCS-7 Deep Learning'
    CHECK (end_time > start_time)
);

-- ---------------------------------------------------------------------------
-- domain_categories: replaces the list that was hard-coded in the SNI
-- extractor, so the admin can edit it without changing code.
-- ---------------------------------------------------------------------------
CREATE TABLE domain_categories (
    domain    TEXT PRIMARY KEY,                       -- parent domain, e.g. facebook.com
    category  TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- policies: the decision table. For each role and category:
-- what to do during class time and what to do outside class time.
-- Categories not listed here are allowed (academic traffic is never blocked).
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    role           TEXT NOT NULL CHECK (role IN ('guest', 'student', 'faculty', 'admin')),
    category       TEXT NOT NULL,
    during_class   TEXT NOT NULL CHECK (during_class IN ('ALLOW', 'BLOCK')),
    outside_class  TEXT NOT NULL CHECK (outside_class IN ('ALLOW', 'BLOCK')),
    PRIMARY KEY (role, category)                      -- one rule per role + category
);
