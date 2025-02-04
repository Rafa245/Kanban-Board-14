import { JwtPayload, jwtDecode } from 'jwt-decode';

class AuthService {
  getProfile() {
    // Get the token from localStorage
    const token = this.getToken();

    // If the token exists, decode it and return the profile
    if (token) {
      try {
        return jwtDecode<JwtPayload>(token);
      } catch (error) {
        console.error('Error decoding token:', error);
        return null; // Return null if decoding fails
      }
    }
    return null; // If there's no token, return null
  }

  loggedIn() {
    // Check if a user is logged in by checking if the token exists and is not expired
    const token = this.getToken();
    return token && !this.isTokenExpired(token); // If the token exists and is not expired, user is logged in
  }
  
  isTokenExpired(token: string) {
    try {
      // Decode the token to check if it has an expiration claim
      const decoded = jwtDecode<JwtPayload>(token);
      
      if (decoded.exp) {
        // If there's an exp claim, check if the token is expired
        return decoded.exp < Date.now() / 1000; // Compare the expiration with the current time (in seconds)
      }
      return false; // If no exp claim, treat the token as not expired
    } catch (error) {
      console.error('Error decoding token:', error);
      return true; // If there's an error decoding the token, consider it expired
    }
  }

  getToken(): string | null {
    // Retrieve the token from localStorage
    return localStorage.getItem('token');
  }

  login(idToken: string) {
    // Store the received token in localStorage
    localStorage.setItem('token', idToken);

    // Redirect to the Kanban board page
    window.location.href = '/';
  }

  logout() {
    // Remove the token from localStorage
    localStorage.removeItem('token');

    // Redirect to the login page
    window.location.href = '/';
  }
}

export default new AuthService();
