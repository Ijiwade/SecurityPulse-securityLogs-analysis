-- Failed Login Ranking 
/*Which users have the most failed authentication attempts, and how do they rank?*/

WITH fail_counts AS ( 
SELECT 
  user_id, 
  SUM(CASE 
      WHEN auth_result = 'FAIL' 
      THEN 1 ELSE 0 
      END
     ) AS fail_count
FROM auth_events
GROUP BY user_id
),

fail_ranked AS (
SELECT
  *,
  RANK()OVER(ORDER BY fail_count DESC) AS fail_rank
FROM fail_counts
) 

SELECT
	u.user_id, 
    u.full_name, 
    fr.fail_count, 
    fr.fail_rank
FROM users u 
JOIN fail_ranked fr
	ON fr.user_id = u.user_id
ORDER BY fr.fail_count DESC;
