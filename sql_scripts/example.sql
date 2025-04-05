-- Example SQL file with various security issues

-- 1. Plain text password
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255) DEFAULT 'admin123'
);

-- 2. Unsafe dynamic SQL
DECLARE @sql NVARCHAR(MAX)
SET @sql = 'SELECT * FROM users WHERE username = ''' + @username + ''''
EXEC(@sql)

-- 3. Sensitive data exposure
SELECT * FROM users WHERE password = 'plaintext123';

-- 4. SQL Injection risk
SELECT * FROM users WHERE username = @username + ' OR 1=1';

-- 5. Privilege escalation
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%';
ALTER USER 'admin'@'%' IDENTIFIED BY 'newpassword';

-- 6. Data exfiltration
SELECT * INTO OUTFILE '/var/lib/mysql-files/users.csv'
FROM users;

-- 7. Unsafe file operations
LOAD_FILE('/etc/passwd');

-- 8. Unsafe string concatenation
SELECT * FROM users WHERE username = @username + ' OR 1=1';

-- 9. Commented out code (potential security risk)
-- DROP TABLE users;
-- DELETE FROM users WHERE 1=1;

-- 10. Schema modification
ALTER TABLE users ADD COLUMN credit_card VARCHAR(255);

-- 11. Complex queries (potential performance issues)
SELECT u.*, 
       p.*,
       o.*,
       c.*
FROM users u
LEFT JOIN profiles p ON u.id = p.user_id
LEFT JOIN orders o ON u.id = o.user_id
LEFT JOIN customers c ON u.id = c.user_id
WHERE u.status = 'active'
AND p.type = 'premium'
AND o.total > 1000
AND c.region = 'EU';