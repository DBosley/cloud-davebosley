const express = require('express');
const cors = require('cors');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const app = express();
app.use(cors());
app.use(express.json());

// Environment variables (set these in DO App Platform)
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN || 'dev-vs44iwncf3g80gpn.us.auth0.com';
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_ROLE_ID = process.env.AUTH0_ROLE_ID || 'rol_YLWi3mMumKCyw2jX';

// JWT middleware to verify Auth0 tokens
const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
    }),
    audience: `https://${AUTH0_DOMAIN}/api/v2/`,
    issuer: `https://${AUTH0_DOMAIN}/`,
    algorithms: ['RS256']
}).unless({ path: ['/health'] });

// Verify access tokens from Auth0
const verifyToken = jwt({
    secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
    }),
    audience: 'https://cloud-api.davebosley.com',
    issuer: `https://${AUTH0_DOMAIN}/`,
    algorithms: ['RS256']
});

// Check admin claim middleware
const checkAdmin = (req, res, next) => {
    const adminClaim = req.auth?.['https://cloud.davebosley.com/admin'];
    if (adminClaim !== true) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Get Management API token
let mgmtToken = null;
let mgmtTokenExpiry = 0;

async function getManagementToken() {
    if (mgmtToken && Date.now() < mgmtTokenExpiry) {
        return mgmtToken;
    }

    const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'client_credentials',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            audience: `https://${AUTH0_DOMAIN}/api/v2/`
        })
    });

    if (!response.ok) {
        throw new Error('Failed to get management token');
    }

    const data = await response.json();
    mgmtToken = data.access_token;
    mgmtTokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
    return mgmtToken;
}

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// List all users with their approval status
app.get('/users', verifyToken, checkAdmin, async (req, res) => {
    try {
        const token = await getManagementToken();

        // Get all users
        const usersResponse = await fetch(
            `https://${AUTH0_DOMAIN}/api/v2/users?per_page=100&include_totals=false`,
            { headers: { Authorization: `Bearer ${token}` } }
        );

        if (!usersResponse.ok) {
            throw new Error('Failed to fetch users');
        }

        const users = await usersResponse.json();

        // Get users with the approved role
        const roleUsersResponse = await fetch(
            `https://${AUTH0_DOMAIN}/api/v2/roles/${AUTH0_ROLE_ID}/users`,
            { headers: { Authorization: `Bearer ${token}` } }
        );

        const approvedUserIds = new Set();
        if (roleUsersResponse.ok) {
            const roleUsers = await roleUsersResponse.json();
            roleUsers.forEach(u => approvedUserIds.add(u.user_id));
        }

        // Combine data
        const result = users.map(user => ({
            user_id: user.user_id,
            email: user.email,
            name: user.name,
            picture: user.picture,
            last_login: user.last_login,
            approved: approvedUserIds.has(user.user_id)
        }));

        res.json(result);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: error.message });
    }
});

// Approve user (assign role)
app.post('/users/:userId/approve', verifyToken, checkAdmin, async (req, res) => {
    try {
        const token = await getManagementToken();
        const { userId } = req.params;

        const response = await fetch(
            `https://${AUTH0_DOMAIN}/api/v2/roles/${AUTH0_ROLE_ID}/users`,
            {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ users: [userId] })
            }
        );

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to approve user: ${error}`);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error approving user:', error);
        res.status(500).json({ error: error.message });
    }
});

// Revoke user (remove role)
app.post('/users/:userId/revoke', verifyToken, checkAdmin, async (req, res) => {
    try {
        const token = await getManagementToken();
        const { userId } = req.params;

        const response = await fetch(
            `https://${AUTH0_DOMAIN}/api/v2/roles/${AUTH0_ROLE_ID}/users`,
            {
                method: 'DELETE',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ users: [userId] })
            }
        );

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to revoke user: ${error}`);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error revoking user:', error);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Admin API running on port ${PORT}`);
});
