/**
 * Hearth and Heal - Authentication Logic
 * Robust system with Email Verification, Password hashing, and 2FA OTP.
 */

const Auth = {
    // Relative path works both locally and in production, fallback to 3000 for file://
    API_BASE: window.location.protocol === 'file:' ? 'http://localhost:3000' : '',
    CURRENT_USER_KEY: 'hearth_current_user',
    JWT_KEY: 'hearth_jwt_token',

    // Initialize session
    checkSession: () => {
        const currentUser = Auth.getCurrentUser();
        const path = window.location.pathname;
        // Improve page extraction: handle / correctly and query params
        let pageName = path.split('/').pop().split('?')[0].toLowerCase();

        // Explicitly handle root path or empty extraction
        if (path === '/' || pageName === '') {
            pageName = 'index.html';
        }

        const authPages = ['login.html', 'signup.html', 'forgot-password.html'];
        // Pages that are accessible without login (Homepage, Mission, Contact, Services, Donate)
        const publicPages = ['index.html', 'mission.html', 'contact.html', 'services.html', 'donate.html'];

        console.log(`[Auth] Checking access for: ${pageName}. Logged in: ${!!currentUser}`);

        if (currentUser) {
            // Logged in users: redirect away from auth pages to home
            if (authPages.includes(pageName)) {
                window.location.href = 'index.html';
            }
            Auth.updateUI(true);
        } else {
            // Not logged in
            // Allow access ONLY if it's an auth page OR a public page
            if (authPages.includes(pageName) || publicPages.includes(pageName)) {
                Auth.updateUI(false);
            } else {
                console.warn(`[Auth] Access denied to ${pageName}. Redirecting to login.`);
                // Restricted page (Shop, Cart, Account, etc.) -> Redirect to login
                window.location.href = 'login.html';
            }
        }
    },

    getCurrentUser: () => JSON.parse(localStorage.getItem(Auth.CURRENT_USER_KEY)),
    setCurrentUser: (user) => localStorage.setItem(Auth.CURRENT_USER_KEY, JSON.stringify(user)),
    setToken: (token) => localStorage.setItem(Auth.JWT_KEY, token),
    logout: () => {
        localStorage.removeItem(Auth.CURRENT_USER_KEY);
        localStorage.removeItem(Auth.JWT_KEY);
        window.location.href = 'login.html';
    },

    updateUI: (isLoggedIn) => {
        const authLink = document.getElementById('auth-link');
        const loginBtn = document.getElementById('login-btn');
        const target = authLink || loginBtn;

        if (target) {
            if (isLoggedIn) {
                target.textContent = 'Account';
                target.href = 'account.html';
                target.onclick = null;
            } else {
                target.textContent = 'Login';
                target.href = 'login.html';
                target.onclick = null;
            }
        }
    },

    /* -------------------- API WRAPPERS -------------------- */

    // SIGNUP STEP 1
    requestSignupVerification: async (email) => {
        try {
            const response = await fetch(`${Auth.API_BASE}/request-verification`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const data = await response.json();
            if (response.ok) {
                Auth._signupRef = data.ref;
                Auth._signupEmail = email;
                return { success: true };
            }
            return { success: false, message: data.error };
        } catch (err) {
            return { success: false, message: 'Server unreachable' };
        }
    },

    // SIGNUP STEP 2
    completeSignup: async (code, password) => {
        try {
            const response = await fetch(`${Auth.API_BASE}/verify-email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ref: Auth._signupRef, code, password })
            });
            const data = await response.json();
            if (response.ok) return { success: true };
            return { success: false, message: data.error };
        } catch (err) {
            return { success: false, message: 'Server unreachable' };
        }
    },

    // LOGIN STEP 1
    login: async (email, password) => {
        try {
            const response = await fetch(`${Auth.API_BASE}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await response.json();
            if (response.ok) {
                Auth._loginRef = data.ref;
                Auth._loginEmail = email;
                return { success: true };
            }
            return { success: false, message: data.error };
        } catch (err) {
            return { success: false, message: 'Server unreachable' };
        }
    },

    // LOGIN STEP 2 (OTP)
    verifyOTP: async (code) => {
        try {
            const response = await fetch(`${Auth.API_BASE}/verify-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ref: Auth._loginRef, otp: code })
            });
            const data = await response.json();
            if (response.ok && data.success) {
                Auth.setToken(data.token);
                Auth.setCurrentUser(data.user);
                return { success: true };
            }
            return { success: false, message: data.error };
        } catch (err) {
            return { success: false, message: 'Server unreachable' };
        }
    },

    // PASSWORD RESET STEP 1
    requestReset: async (email) => {
        try {
            const response = await fetch(`${Auth.API_BASE}/reset/request`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const data = await response.json();
            if (response.ok) {
                Auth._resetRef = data.ref;
                return { success: true };
            }
            return { success: false, message: data.error };
        } catch (err) {
            return { success: false, message: 'Server unreachable' };
        }
    },

    // PASSWORD RESET STEP 2
    completeReset: async (token, newPassword) => {
        try {
            const response = await fetch(`${Auth.API_BASE}/reset/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ref: Auth._resetRef, token, newPassword })
            });
            const data = await response.json();
            if (response.ok) return { success: true };
            return { success: false, message: data.error };
        } catch (err) {
            return { success: false, message: 'Server unreachable' };
        }
    },

    // OTP REQUEST (Direct)
    requestOTP: async (identifier) => {
        try {
            const response = await fetch(`${Auth.API_BASE}/login/request`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: identifier })
            });
            const data = await response.json();
            if (response.ok) {
                Auth._loginRef = data.ref;
                // For development, you can see the code in the response
                if (data.code) console.log("Development OTP Code:", data.code);
                return { success: true };
            }
            return { success: false, message: data.error };
        } catch (err) {
            return { success: false, message: 'Server unreachable' };
        }
    }
};

Auth.checkSession();
