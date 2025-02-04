import { UserLogin } from "../interfaces/UserLogin";
import { jwtDecode, JwtPayload } from 'jwt-decode';

const login = async (userInfo: UserLogin) => {
  try {
    const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:3001'; // Ensure correct base URL for production
    const response = await fetch(`${apiUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userInfo),
    });

    // Check if the response is OK (status 200-299)
    if (!response.ok) {
      const errorResponse = await response.json();
      console.error('Login error:', errorResponse);
      throw new Error(errorResponse?.message || 'Login failed');
    }

    // Parse the response JSON
    const data = await response.json();

    // Ensure there's a token to store
    if (data.token) {
      localStorage.setItem('token', data.token); // Store the JWT in localStorage

      // Optional: Decode the token to check for expiration
      const decoded: JwtPayload = jwtDecode(data.token);
      const isExpired = decoded.exp ? decoded.exp < Date.now() / 1000 : true;
      if (isExpired) {
        throw new Error('Token has expired');
      }
    } else {
      throw new Error('No token received');
    }

    return data; 
  } catch (error) {
    console.error('Error during login:', error);
    throw error; // Rethrow for the caller to handle
  }
};

export { login };
