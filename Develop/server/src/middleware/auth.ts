import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

// Extend Express's Request type to include user property
declare module 'express' {
  export interface Request {
    user?: JwtPayload;
  }
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction): Response | void => {
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
      req.user = decoded as JwtPayload;  // Attach decoded token to request if valid
      return next(); // Proceed to the next middleware or route handler
    } else {
      console.error('Malformed token payload');
      return res.status(403).json({ message: 'Malformed token payload' });
    }
  });
};
