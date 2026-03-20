PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS auth_events;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS ip_reputation;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  user_id INTEGER PRIMARY KEY,
  full_name TEXT,
  dept TEXT,
  role TEXT,
  risk_tier TEXT
);

CREATE TABLE devices (
  device_id INTEGER PRIMARY KEY,
  user_id INTEGER,
  device_type TEXT,
  os TEXT,
  is_managed INTEGER,
  first_seen_ts TEXT,
  FOREIGN KEY(user_id) REFERENCES users(user_id)
);

CREATE TABLE ip_reputation (
  ip TEXT PRIMARY KEY,
  country TEXT,
  risk_score INTEGER,
  is_tor_exit INTEGER,
  is_datacenter INTEGER
);

CREATE TABLE auth_events (
  event_id INTEGER PRIMARY KEY,
  event_ts TEXT,
  user_id INTEGER,
  device_id INTEGER,
  ip TEXT,
  city TEXT,
  auth_result TEXT,
  mfa_used INTEGER,
  app TEXT,
  FOREIGN KEY(user_id) REFERENCES users(user_id),
  FOREIGN KEY(device_id) REFERENCES devices(device_id),
  FOREIGN KEY(ip) REFERENCES ip_reputation(ip)
);

CREATE INDEX idx_auth_user_ts ON auth_events(user_id, event_ts);
CREATE INDEX idx_auth_ip ON auth_events(ip);
CREATE INDEX idx_devices_user ON devices(user_id);

BEGIN TRANSACTION;

-- -------------------------------------------------------------------
-- USERS (120)
-- -------------------------------------------------------------------
WITH RECURSIVE nums(n) AS (
  SELECT 1
  UNION ALL
  SELECT n + 1 FROM nums WHERE n < 120
)
INSERT INTO users (user_id, full_name, dept, role, risk_tier)
SELECT
  n,
  (CASE (n % 15)
     WHEN 0 THEN 'Amina'
     WHEN 1 THEN 'James'
     WHEN 2 THEN 'Noah'
     WHEN 3 THEN 'Grace'
     WHEN 4 THEN 'Daniel'
     WHEN 5 THEN 'Leila'
     WHEN 6 THEN 'Ibrahim'
     WHEN 7 THEN 'Maya'
     WHEN 8 THEN 'Samuel'
     WHEN 9 THEN 'Lara'
     WHEN 10 THEN 'Victor'
     WHEN 11 THEN 'Sofia'
     WHEN 12 THEN 'Ethan'
     WHEN 13 THEN 'Hannah'
     ELSE 'Oliver'
   END)
   || ' ' ||
  (CASE (n % 17)
     WHEN 0 THEN 'Carter'
     WHEN 1 THEN 'Bello'
     WHEN 2 THEN 'Okafor'
     WHEN 3 THEN 'Mensah'
     WHEN 4 THEN 'Hughes'
     WHEN 5 THEN 'Wilson'
     WHEN 6 THEN 'Taylor'
     WHEN 7 THEN 'Davis'
     WHEN 8 THEN 'Johnson'
     WHEN 9 THEN 'Anderson'
     WHEN 10 THEN 'Moore'
     WHEN 11 THEN 'Thomas'
     WHEN 12 THEN 'Brown'
     WHEN 13 THEN 'White'
     WHEN 14 THEN 'Jones'
     WHEN 15 THEN 'Smith'
     ELSE 'Walker'
   END) AS full_name,
  CASE (n % 8)
    WHEN 0 THEN 'IT'
    WHEN 1 THEN 'Finance'
    WHEN 2 THEN 'Operations'
    WHEN 3 THEN 'Sales'
    WHEN 4 THEN 'Engineering'
    WHEN 5 THEN 'HR'
    WHEN 6 THEN 'Legal'
    ELSE 'Support'
  END AS dept,
  CASE (n % 6)
    WHEN 0 THEN 'Admin'
    WHEN 1 THEN 'Analyst'
    WHEN 2 THEN 'Manager'
    WHEN 3 THEN 'Developer'
    WHEN 4 THEN 'Rep'
    ELSE 'Associate'
  END AS role,
  CASE
    WHEN n % 11 = 0 THEN 'High'
    WHEN n % 3 = 0 THEN 'Medium'
    ELSE 'Low'
  END AS risk_tier
FROM nums;

-- Make a few named users for easier anomaly interpretation
UPDATE users SET full_name='James Carter', dept='IT', role='Admin', risk_tier='High' WHERE user_id=2;
UPDATE users SET full_name='Amina Bello', dept='Finance', role='Analyst', risk_tier='Medium' WHERE user_id=17;
UPDATE users SET full_name='Chidi Okafor', dept='Operations', role='Manager', risk_tier='Medium' WHERE user_id=33;
UPDATE users SET full_name='Noah Hughes', dept='Engineering', role='Developer', risk_tier='Medium' WHERE user_id=44;

-- -------------------------------------------------------------------
-- DEVICES (2 per user = 240)
-- -------------------------------------------------------------------
WITH RECURSIVE nums(n) AS (
  SELECT 1
  UNION ALL
  SELECT n + 1 FROM nums WHERE n < 240
)
INSERT INTO devices (device_id, user_id, device_type, os, is_managed, first_seen_ts)
SELECT
  n,
  CAST((n - 1) / 2 AS INTEGER) + 1 AS user_id,
  CASE ((n - 1) % 4)
    WHEN 0 THEN 'Laptop'
    WHEN 1 THEN 'Phone'
    WHEN 2 THEN 'Laptop'
    ELSE 'Tablet'
  END AS device_type,
  CASE ((n - 1) % 6)
    WHEN 0 THEN 'Windows'
    WHEN 1 THEN 'Android'
    WHEN 2 THEN 'macOS'
    WHEN 3 THEN 'iOS'
    WHEN 4 THEN 'Linux'
    ELSE 'Windows'
  END AS os,
  CASE WHEN n % 5 = 0 THEN 0 ELSE 1 END AS is_managed,
  datetime('2024-01-01 08:00:00', '+' || (n * 37) || ' hours') AS first_seen_ts
FROM nums;

-- -------------------------------------------------------------------
-- IP REPUTATION
-- Fixed high-signal IPs first, then generated IPs
-- -------------------------------------------------------------------
INSERT INTO ip_reputation (ip, country, risk_score, is_tor_exit, is_datacenter) VALUES
('81.2.69.1',      'UK', 10, 0, 0),
('81.2.69.2',      'UK', 12, 0, 0),
('185.220.101.1',  'NL', 92, 1, 0),
('45.83.64.10',    'DE', 85, 0, 1),
('197.210.54.7',   'NG', 25, 0, 0),
('203.0.113.9',    'US', 60, 0, 1),
('102.89.23.4',    'GH', 30, 0, 0),
('203.0.113.88',   'US', 78, 0, 1);

WITH RECURSIVE nums(n) AS (
  SELECT 1
  UNION ALL
  SELECT n + 1 FROM nums WHERE n < 180
)
INSERT INTO ip_reputation (ip, country, risk_score, is_tor_exit, is_datacenter)
SELECT
  printf('10.%d.%d.%d',
    10 + ((n - 1) % 40),
    (n * 3) % 250,
    1 + ((n * 7) % 250)
  ) AS ip,
  CASE (n % 8)
    WHEN 0 THEN 'UK'
    WHEN 1 THEN 'US'
    WHEN 2 THEN 'DE'
    WHEN 3 THEN 'FR'
    WHEN 4 THEN 'CA'
    WHEN 5 THEN 'NG'
    WHEN 6 THEN 'GH'
    ELSE 'NL'
  END AS country,
  CASE
    WHEN n % 29 = 0 THEN 88
    WHEN n % 17 = 0 THEN 76
    WHEN n % 13 = 0 THEN 65
    ELSE 8 + (n % 45)
  END AS risk_score,
  CASE WHEN n % 31 = 0 THEN 1 ELSE 0 END AS is_tor_exit,
  CASE WHEN n % 19 = 0 THEN 1 ELSE 0 END AS is_datacenter
FROM nums;

-- -------------------------------------------------------------------
-- BASELINE AUTH EVENTS (6000 across 2025)
-- -------------------------------------------------------------------
WITH RECURSIVE nums(n) AS (
  SELECT 1
  UNION ALL
  SELECT n + 1 FROM nums WHERE n < 6000
)
INSERT INTO auth_events (
  event_id, event_ts, user_id, device_id, ip, city, auth_result, mfa_used, app
)
SELECT
  n AS event_id,
  datetime('2025-01-01 00:00:00', '+' || ((n - 1) * 87) || ' minutes') AS event_ts,
  ((n * 7 - 1) % 120) + 1 AS user_id,
  (((( (n * 7 - 1) % 120) + 1) - 1) * 2) + CASE WHEN n % 3 = 0 THEN 2 ELSE 1 END AS device_id,
  CASE
    WHEN n % 53 = 0 THEN '185.220.101.1'
    WHEN n % 41 = 0 THEN '45.83.64.10'
    WHEN n % 37 = 0 THEN '203.0.113.9'
    WHEN n % 19 = 0 THEN '197.210.54.7'
    WHEN n % 17 = 0 THEN '102.89.23.4'
    WHEN n % 23 = 0 THEN '81.2.69.1'
    WHEN n % 29 = 0 THEN '81.2.69.2'
    ELSE printf('10.%d.%d.%d',
      10 + (((( (n - 1) % 180) + 1) - 1) % 40),
      ((((n - 1) % 180) + 1) * 3) % 250,
      1 + ((((n - 1) % 180) + 1) * 7) % 250
    )
  END AS ip,
  CASE
    WHEN n % 53 = 0 THEN 'Unknown'
    WHEN n % 41 = 0 THEN 'Berlin'
    WHEN n % 37 = 0 THEN 'New York'
    WHEN n % 19 = 0 THEN 'Lagos'
    WHEN n % 17 = 0 THEN 'Accra'
    WHEN n % 23 = 0 THEN 'London'
    WHEN n % 29 = 0 THEN 'Lincoln'
    ELSE
      CASE (((n - 1) % 8))
        WHEN 0 THEN 'London'
        WHEN 1 THEN 'New York'
        WHEN 2 THEN 'Berlin'
        WHEN 3 THEN 'Paris'
        WHEN 4 THEN 'Toronto'
        WHEN 5 THEN 'Lagos'
        WHEN 6 THEN 'Accra'
        ELSE 'Amsterdam'
      END
  END AS city,
  CASE
    WHEN n % 11 = 0 THEN 'FAIL'
    WHEN n % 13 = 0 THEN 'FAIL'
    WHEN n % 47 = 0 THEN 'FAIL'
    ELSE 'SUCCESS'
  END AS auth_result,
  CASE
    WHEN (n % 11 = 0 OR n % 13 = 0 OR n % 47 = 0) THEN 0
    WHEN n % 5 = 0 THEN 0
    ELSE 1
  END AS mfa_used,
  CASE (n % 6)
    WHEN 0 THEN 'Email'
    WHEN 1 THEN 'CRM'
    WHEN 2 THEN 'AdminPanel'
    WHEN 3 THEN 'Repo'
    WHEN 4 THEN 'VPN'
    ELSE 'Payroll'
  END AS app
FROM nums;

-- -------------------------------------------------------------------
-- EXPLICIT SUSPICIOUS PATTERNS
-- -------------------------------------------------------------------

-- User 2: 3 fails then success (lock/review) + impossible travel + TOR/datacenter behavior
INSERT INTO auth_events (event_id, event_ts, user_id, device_id, ip, city, auth_result, mfa_used, app) VALUES
(6001, '2025-07-14 01:44:00', 2, 4, '81.2.69.2',     'Lincoln', 'SUCCESS', 1, 'AdminPanel'),
(6002, '2025-07-14 01:45:00', 2, 4, '185.220.101.1', 'Unknown', 'FAIL',    0, 'AdminPanel'),
(6003, '2025-07-14 01:46:00', 2, 4, '185.220.101.1', 'Unknown', 'FAIL',    0, 'AdminPanel'),
(6004, '2025-07-14 01:47:00', 2, 4, '185.220.101.1', 'Unknown', 'FAIL',    0, 'AdminPanel'),
(6005, '2025-07-14 01:48:00', 2, 4, '185.220.101.1', 'Unknown', 'SUCCESS', 0, 'AdminPanel'),
(6006, '2025-07-14 03:10:00', 2, 3, '45.83.64.10',   'Berlin',  'SUCCESS', 0, 'AdminPanel');

-- User 17: brute-force style pattern only
INSERT INTO auth_events (event_id, event_ts, user_id, device_id, ip, city, auth_result, mfa_used, app) VALUES
(6007, '2025-05-02 09:10:00', 17, 34, '102.89.23.4', 'Accra',   'FAIL',    0, 'VPN'),
(6008, '2025-05-02 09:11:00', 17, 34, '102.89.23.4', 'Accra',   'FAIL',    0, 'VPN'),
(6009, '2025-05-02 09:12:00', 17, 34, '102.89.23.4', 'Accra',   'SUCCESS', 1, 'VPN');

-- User 33: impossible travel only
INSERT INTO auth_events (event_id, event_ts, user_id, device_id, ip, city, auth_result, mfa_used, app) VALUES
(6010, '2025-08-18 07:58:00', 33, 65, '81.2.69.1',   'London',  'SUCCESS', 1, 'CRM'),
(6011, '2025-08-18 08:01:00', 33, 65, '203.0.113.9', 'New York','SUCCESS', 1, 'CRM');

-- User 44: 3 fails before success
INSERT INTO auth_events (event_id, event_ts, user_id, device_id, ip, city, auth_result, mfa_used, app) VALUES
(6012, '2025-09-09 20:00:00', 44, 88, '81.2.69.1',   'London',  'FAIL',    0, 'Repo'),
(6013, '2025-09-09 20:01:00', 44, 88, '81.2.69.1',   'London',  'FAIL',    0, 'Repo'),
(6014, '2025-09-09 20:02:00', 44, 88, '81.2.69.1',   'London',  'FAIL',    0, 'Repo'),
(6015, '2025-09-09 20:03:00', 44, 88, '81.2.69.1',   'London',  'SUCCESS', 1, 'Repo');

COMMIT;

-- -------------------------------------------------------------------
-- SANITY CHECKS
-- -------------------------------------------------------------------
SELECT COUNT(*) AS users_count FROM users;
SELECT COUNT(*) AS devices_count FROM devices;
SELECT COUNT(*) AS ip_count FROM ip_reputation;
SELECT COUNT(*) AS auth_events_count FROM auth_events;
