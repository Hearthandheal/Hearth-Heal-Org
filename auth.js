/**
 * Hearth and Heal - Authentication Logic
 * Handles Login, Signup, Password Reset, and Session Protection
 * Enhanced with password hashing and input sanitization
 */

const Auth = {
    // Keys for localStorage
    USERS_KEY: 'hearth_users',
    CURRENT_USER_KEY: 'hearth_current_user',

    // Simple password hashing using SHA-256
    hashPassword: async (password) => {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // Sanitize input to prevent XSS
    sanitizeInput: (input) => {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    },

    // Initialize (helper to get data)
    getUsers: () => JSON.parse(localStorage.getItem(Auth.USERS_KEY) || '[]'),
    setUsers: (users) => localStorage.setItem(Auth.USERS_KEY, JSON.stringify(users)),
    getCurrentUser: () => JSON.parse(localStorage.getItem(Auth.CURRENT_USER_KEY)),
    setCurrentUser: (user) => localStorage.setItem(Auth.CURRENT_USER_KEY, JSON.stringify(user)),

    /**
     * Check if user is logged in.
     * If not, and not on an auth page, redirect to login.
     */
    checkSession: () => {
        const currentUser = Auth.getCurrentUser();
        const path = window.location.pathname;
        const pageName = path.split('/').pop().toLowerCase();

        // Pages that require being logged OUT
        const authPages = ['login.html', 'signup.html', 'forgot-password.html'];

        // Pages that require being logged IN (Empty means default public access)
        const protectedPages = [];

        if (currentUser) {
            // Logged In
            if (authPages.includes(pageName)) {
                window.location.href = 'index.html';
            }
            Auth.updateUI(true);
        } else {
            // Logged Out
            if (protectedPages.includes(pageName)) {
                window.location.href = 'login.html';
            }
            Auth.updateUI(false);
        }
    },

    updateUI: (isLoggedIn) => {
        const authLink = document.getElementById('auth-link');
        const loginBtn = document.getElementById('login-btn');
        const target = authLink || loginBtn;

        if (target) {
            if (isLoggedIn) {
                target.textContent = 'Account';
                if (target.tagName === 'A') {
                    target.href = 'account.html';
                    target.onclick = null; // Let the link work normally
                } else {
                    // For button, redirect to account
                    target.onclick = () => window.location.href = 'account.html';
                }
            } else {
                target.textContent = 'Login';
                if (target.tagName === 'A') {
                    target.href = 'login.html';
                    target.onclick = null;
                } else {
                    target.onclick = () => window.location.href = 'login.html';
                }
            }
        }
    },

    /**
     * Login User
     * @param {string} email 
     * @param {string} password 
     */
    login: async (email, password) => {
        const users = Auth.getUsers();
        const hashedPassword = await Auth.hashPassword(password);
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.password === hashedPassword);

        if (user) {
            Auth.setCurrentUser({ email: user.email, name: user.name || user.email.split('@')[0], bio: user.bio });
            return { success: true };
        } else {
            return { success: false, message: 'Invalid email or password' };
        }
    },

    /**
     * Register New User
     * @param {string} email 
     * @param {string} password 
     */
    signup: async (email, password) => {
        const users = Auth.getUsers();

        // Sanitize email input
        email = Auth.sanitizeInput(email.trim());

        if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
            return { success: false, message: 'Email already exists' };
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email || !emailRegex.test(email)) {
            return { success: false, message: 'Please enter a valid email address' };
        }

        if (!password || password.length < 6) {
            return { success: false, message: 'Password must be at least 6 characters long' };
        }

        // Hash password before storing
        const hashedPassword = await Auth.hashPassword(password);
        const newUser = { email, password: hashedPassword, name: email.split('@')[0], bio: '' };
        users.push(newUser);
        Auth.setUsers(users);
        Auth.setCurrentUser({ email: newUser.email, name: newUser.name, bio: newUser.bio });
        return { success: true };
    },

    /**
     * Update User Profile
     * @param {object} data { name, bio }
     */
    updateProfile: (data) => {
        const currentUser = Auth.getCurrentUser();
        if (!currentUser) return { success: false, message: 'Not logged in' };

        const users = Auth.getUsers();
        const userIndex = users.findIndex(u => u.email === currentUser.email);

        if (userIndex !== -1) {
            // Update users array
            users[userIndex].name = data.name;
            users[userIndex].bio = data.bio;
            Auth.setUsers(users);

            // Update current user session
            currentUser.name = data.name;
            currentUser.bio = data.bio;
            Auth.setCurrentUser(currentUser);
            return { success: true };
        }
        return { success: false, message: 'User not found' };
    },

    /**
     * Change Password
     * @param {string} oldPassword 
     * @param {string} newPassword 
     */
    changePassword: async (oldPassword, newPassword) => {
        const currentUser = Auth.getCurrentUser();
        if (!currentUser) return { success: false, message: 'Not logged in' };

        const users = Auth.getUsers();
        const userIndex = users.findIndex(u => u.email === currentUser.email);

        if (userIndex === -1) return { success: false, message: 'User not found' };

        const hashedOldPassword = await Auth.hashPassword(oldPassword);
        if (users[userIndex].password !== hashedOldPassword) {
            return { success: false, message: 'Incorrect current password' };
        }

        if (newPassword.length < 6) {
            return { success: false, message: 'New password must be at least 6 characters' };
        }

        const hashedNewPassword = await Auth.hashPassword(newPassword);
        users[userIndex].password = hashedNewPassword;
        Auth.setUsers(users);
        return { success: true };
    },

    /**
     * Reset Password (Forgot Password flow)
     * @param {string} email 
     * @param {string} newPassword 
     */
    resetPassword: (email, newPassword) => {
        const users = Auth.getUsers();
        const userIndex = users.findIndex(u => u.email.toLowerCase() === email.toLowerCase());

        if (userIndex !== -1) {
            users[userIndex].password = newPassword;
            Auth.setUsers(users);
            return { success: true };
        } else {
            return { success: false, message: 'Email not found' };
        }
    },

    /**
     * Request OTP
     * @param {string} identifier 
     * @param {string} type 'email' or 'phone'
     */
    requestOTP: async (identifier, type) => {
        try {
            const response = await fetch('http://localhost:3000/auth/otp/request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier, type })
            });
            const data = await response.json();
            if (response.ok) return { success: true };
            return { success: false, message: data.error || 'Failed to send OTP' };
        } catch (error) {
            console.error(error);
            return { success: false, message: 'Network error' };
        }
    },

    /**
     * Verify OTP
     * @param {string} identifier 
     * @param {string} code 
     */
    verifyOTP: async (identifier, code) => {
        try {
            const response = await fetch('http://localhost:3000/auth/otp/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier, code })
            });
            const data = await response.json();

            if (response.ok && data.success) {
                // Log user in
                Auth.setCurrentUser({ email: identifier, name: data.user.name, bio: '' });
                return { success: true };
            }
            return { success: false, message: data.error || 'Verification failed' };
        } catch (error) {
            console.error(error);
            return { success: false, message: 'Network error' };
        }
    },

    /**
     * Logout
     * ...
     */
    logout: () => {
        localStorage.removeItem(Auth.CURRENT_USER_KEY);
        window.location.href = 'login.html';
    }
};

// Run session check immediately
Auth.checkSession();
