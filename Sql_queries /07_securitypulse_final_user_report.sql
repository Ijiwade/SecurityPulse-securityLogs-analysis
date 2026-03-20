-- SecurityPulse Assembly 
-- securityPulse_final_user_report
WITH latest_event AS ( 
SELECT
  user_id, 
  full_name, 
  dept, 
  role, 
  event_ts, 
  auth_result, 
  ip, 
  app
FROM (
	SELECT
  		u.user_id,
  		u.full_name, 
  		u.dept,
  		u.role,
  		ae.event_id, 
  		ae.event_ts, 
  		ae.auth_result, 
  		ae.ip,
  		ae.app,
  		ROW_NUMBER()OVER(
          PARTITION BY u.user_id 
          ORDER BY event_ts DESC, event_id DESC
        ) AS rn
  	FROM auth_events ae
  	JOIN users u 
  		ON ae.user_id = u.user_id
)
WHERE rn = 1
), 

fail_counts AS ( 
SELECT
  user_id,
  SUM(CASE WHEN auth_result = 'FAIL' THEN 1 ELSE 0 END) AS fail_count
FROM auth_events
GROUP BY user_id
), 

fail_ranked AS ( 
SELECT
  *, 
  RANK()OVER(ORDER BY fail_count DESC) AS fail_rank
FROM fail_counts
), 

bf_seq AS (
SELECT
  ae.*, 
  LAG(ae.auth_result)OVER(PARTITION BY ae.user_id ORDER BY ae.event_ts, ae.event_id) AS prev_result, 
  LAG(ae.auth_result, 2)OVER(PARTITION BY ae.user_id ORDER BY ae.event_ts, ae.event_id) AS prev2_result,
  LAG(ae.event_ts)OVER(PARTITION BY ae.user_id ORDER BY ae.event_ts, ae.event_id) AS prev_ts,
  LAG(ae.event_ts, 2)OVER(PARTITION BY ae.user_id ORDER BY ae.event_ts, ae.event_id) AS prev2_ts
FROM auth_events ae
),

bf_scored AS (
SELECT
  *, 
  (julianday(event_ts) - julianday(prev_ts)) * 1440.0 AS min_btw_cur_prev, 
  (julianday(prev_ts) - julianday(prev2_ts)) * 1440.0 AS min_btw_prev_prev2
FROM bf_seq
), 

bf_hits AS ( 
SELECT
  user_id, 
  event_ts AS success_ts, 
  ip, 
  app, 
  min_btw_prev_prev2
FROM bf_scored
WHERE auth_result = 'SUCCESS'
  AND prev_result = 'FAIL'
  AND prev2_result = 'FAIL'
  AND min_btw_cur_prev <= 5
  AND min_btw_prev_prev2 <= 5
), 

bf_by_user AS ( 
SELECT
  user_id,
  1 AS bruteforce_flag, 
  COUNT(*) AS bf_count, 
  MAX(success_ts) AS bf_latest_ts
FROM bf_hits
GROUP BY user_id
), 
-- ImpossibleTravel Detection 
imt_seq AS( 
SELECT
  ae.ip, 
  ae.user_id, 
  ae.event_id,
  ae.event_ts,
  ae.auth_result,
  ir.country,
  LAG(ir.country)OVER(
    PARTITION BY ae.user_id 
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev_country,
  LAG(ae.event_ts)OVER(
    PARTITION BY ae.user_id 
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev_ts
FROM auth_events ae 
JOIN ip_reputation ir 
  ON ae.ip = ir.ip
),

imt_scored AS ( 
SELECT
  *, 
  (julianday(event_ts) - julianday(prev_ts)) * 24.0 AS hr_btw_logins
FROM imt_seq
), 

imt_hits AS (
SELECT
  user_id, 
  ip,
  event_ts AS travel_ts, 
  prev_ts,
  country, 
  prev_country,
  ROUND(hr_btw_logins,2) AS hours_btw_logins,
  auth_result
FROM imt_scored
WHERE prev_country IS NOT NULL
  AND auth_result = 'SUCCESS'
  AND country <> prev_country
  AND hr_btw_logins <= 4
), 

imt_by_user AS ( 
SELECT
  user_id, 
  1 AS impossible_travel_flag,
  COUNT(*) AS impossible_travel_count, 
  MAX(travel_ts) AS impossible_travel_latest_ts
FROM imt_hits
GROUP BY user_id
), 

-- Login Failure Escalation 
-- Flag accounts where 3 or more consecutive FAIL events occur before a SUCCESS 
esc_b AS ( 
SELECT
  user_id, 
  event_id, 
  event_ts, 
  auth_result, 
  CASE WHEN auth_result = 'FAIL' THEN 1 ELSE 0 END AS fail_flag,
  CASE WHEN auth_result = 'SUCCESS' THEN 1 ELSE 0 END AS success_flag
FROM auth_events
),

esc_g AS ( 
SELECT
  *, 
  SUM(success_flag)OVER(
    PARTITION BY user_id 
    ORDER BY event_ts, event_id
  ) AS success_group
FROM esc_b
), 

esc_s AS ( 
SELECT 
  *, 
  SUM(fail_flag)OVER(
    PARTITION BY user_id, success_group 
    ORDER BY event_ts, event_id
  ) AS fails_in_block
FROM esc_g
), 

esc_final AS ( 
SELECT 
  *, 
  LAG(fails_in_block)OVER(
    PARTITION BY user_id 
    ORDER BY event_ts, event_id
  ) AS fails_before_event
FROM esc_s
), 

esc_hits AS ( 
SELECT
	user_id, 
    event_id, 
    event_ts, 
    auth_result, 
    fails_before_event
FROM esc_final
WHERE auth_result = 'SUCCESS'
	AND COALESCE(fails_before_event,0) >= 3
), 

esc_by_user AS ( 
SELECT 
  user_id, 
  1 AS escalation_flag, 
  COUNT(*) AS escalation_count, 
  MAX(event_ts) AS escalation_latest_ts
FROM esc_hits
GROUP BY user_id
)
 
SELECT
	u.user_id, 
    u.full_name, 
    u.dept, 
    u.role, 
    u.risk_tier, 
    
    le.event_ts		AS latest_event_ts, 
    le.auth_result	AS latest_result,
    le.ip			AS latest_ip, 
    le.app			AS latest_app, 
    
    COALESCE(bbu.bruteforce_flag, 0)	AS bruteforce_flag,
    COALESCE(bbu.bf_count,0)			AS bruteforce_count,
    bbu.bf_latest_ts				AS bruteforce_latest_success_ts,
    
    COALESCE(tbu.impossible_travel_flag,0)	AS impossible_travel_flag,
    COALESCE(tbu.impossible_travel_count,0)	AS impossible_travel_count, 
    tbu.impossible_travel_latest_ts,
    
    COALESCE(ebu.escalation_flag,0)		AS escalation_flag,
    COALESCE(ebu.escalation_count,0)	AS escalation_count, 
    ebu.escalation_latest_ts,
    
    COALESCE(fr.fail_count,0) 			AS fail_count,
    fr.fail_rank
FROM users u 
LEFT JOIN  latest_event le
	ON le.user_id = u.user_id
LEFT JOIN fail_ranked fr 
	ON fr.user_id = u.user_id
LEFT JOIN bf_by_user bbu
	ON bbu.user_id = u.user_id
LEFT JOIN imt_by_user tbu
	ON tbu.user_id = u.user_id
LEFT JOIN esc_by_user ebu
	ON ebu.user_id = u.user_id;
