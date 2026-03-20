-- Login Failure Escalation 
-- Flag accounts where 3 or more consecutive FAIL events occur before a SUCCESS 
WITH b AS ( 
SELECT
  user_id, 
  event_id, 
  event_ts, 
  auth_result, 
  CASE WHEN auth_result = 'FAIL' THEN 1 ELSE 0 END AS fail_flag,
  CASE WHEN auth_result = 'SUCCESS' THEN 1 ELSE 0 END AS success_flag
FROM auth_events
),

g AS ( 
SELECT
  *, 
  SUM(success_flag)OVER(
    PARTITION BY user_id 
    ORDER BY event_ts, event_id
  ) AS success_group
FROM b
), 

s AS ( 
SELECT 
  *, 
  SUM(fail_flag)OVER(
    PARTITION BY user_id, success_group 
    ORDER BY event_ts, event_id
  ) AS fails_in_block
FROM g
), 

final AS ( 
SELECT 
  *, 
  LAG(fails_in_block)OVER(
    PARTITION BY user_id 
    ORDER BY event_ts, event_id
  ) AS fails_before_event
FROM s
)

SELECT
	user_id, 
    event_id, 
    event_ts, 
    auth_result, 
    fails_before_event
FROM final
WHERE auth_result = 'SUCCESS'
	AND COALESCE(fails_before_event,0) >= 3;
