import jwt from 'jsonwebtoken';
export const authenticateToken = (req, res, next) => {
    // Extract token from Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Access token is missing' });
    }
    const secretKey = process.env.JWT_SECRET_KEY;
    if (!secretKey) {
        console.error('JWT_SECRET_KEY is missing from environment variables');
        return res.status(500).json({ message: 'Internal server error, secret key missing' });
    }
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            console.error('JWT verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        if (decoded && typeof decoded === 'object' && 'username' in decoded) {
            req.user = decoded; // Attach decoded token to request if valid
            return next(); // Proceed to the next middleware or route handler
        }
        else {
            console.error('Malformed token payload');
            return res.status(403).json({ message: 'Malformed token payload' });
        }
    });
};
