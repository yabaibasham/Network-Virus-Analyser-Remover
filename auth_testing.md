# Auth-Gated App Testing Playbook (SentinelGrid)

Emergent Google OAuth cannot be completed headless. To test protected routes,
seed a user + session directly in MongoDB and use the session_token via cookie
or `Authorization: Bearer`.

## Step 1: Create Test User & Session (MongoDB: test_database)
```
mongosh --eval "
use('test_database');
var userId = 'user_testauditor01';
var sessionToken = 'test_session_auditor_01';
db.users.updateOne({user_id:userId},{ \$set:{
  user_id:userId, email:'auditor@sentinelgrid.local', name:'Security Auditor',
  picture:'https://via.placeholder.com/150', created_at:new Date().toISOString()
}},{upsert:true});
db.user_sessions.updateOne({session_token:sessionToken},{ \$set:{
  user_id:userId, session_token:sessionToken,
  expires_at:new Date(Date.now()+7*24*60*60*1000), created_at:new Date().toISOString()
}},{upsert:true});
print('Session token: '+sessionToken);
"
```

## Step 2: Backend API checks
```
API=$REACT_APP_BACKEND_URL
# Public (no auth): should be 200
curl -s "$API/api/stats"
# Protected without auth: should be 401
curl -s -o /dev/null -w '%{http_code}\n' "$API/api/devices"
# Protected with auth: should be 200
curl -s "$API/api/devices" -H "Authorization: Bearer test_session_auditor_01"
# /auth/me with token: returns user
curl -s "$API/api/auth/me" -H "Authorization: Bearer test_session_auditor_01"
```

## Step 3: Browser testing (set cookie then load /dashboard)
```
await page.context.add_cookies([{ "name":"session_token","value":"test_session_auditor_01",
  "domain":"<preview-host>","path":"/","httpOnly":true,"secure":true,"sameSite":"None"}])
await page.goto("<preview>/dashboard")
```

## Success indicators
- /api/auth/me returns user; /dashboard loads without redirect to /login.
- Protected endpoints return 401 without token, 200 with token.
- Public: /, /api/stats work unauthenticated.
