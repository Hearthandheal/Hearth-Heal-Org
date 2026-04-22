import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from './AuthContext';
import { useNavigate } from 'react-router-dom';

const API_URL = "https://hearth-heal-api.onrender.com/api";

const profilePictures = [
  "https://api.dicebear.com/7.x/avataaars/svg?seed=Felix",
  "https://api.dicebear.com/7.x/avataaars/svg?seed=Aneka",
  "https://api.dicebear.com/7.x/avataaars/svg?seed=Zoe",
  "https://api.dicebear.com/7.x/avataaars/svg?seed=Jack",
  "https://api.dicebear.com/7.x/avataaars/svg?seed=Lily",
  "https://api.dicebear.com/7.x/avataaars/svg?seed=Max",
];

export default function Profile() {
  const { user, token, logout } = useAuth();
  const navigate = useNavigate();
  const [selectedPicture, setSelectedPicture] = useState(user?.profilePicture || profilePictures[0]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) {
      navigate('/login');
    }
  }, [token, navigate]);

  const updateProfilePicture = async () => {
    setLoading(true);
    try {
      await axios.put(
        `${API_URL}/auth/profile`,
        { profilePicture: selectedPicture },
        { headers: { Authorization: token } }
      );
      
      // Update local storage
      const updatedUser = { ...user, profilePicture: selectedPicture };
      localStorage.setItem('user', JSON.stringify(updatedUser));
      alert('Profile picture updated!');
    } catch (err: any) {
      alert('Error: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-black text-white min-h-screen p-6">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-3xl font-bold mb-8">My Profile</h1>

        {/* Current Profile Card */}
        <div className="bg-zinc-900 p-8 rounded-2xl mb-8">
          <div className="flex items-center gap-6">
            <img
              src={user?.profilePicture || profilePictures[0]}
              alt="Profile"
              className="w-24 h-24 rounded-full border-2 border-green-500"
            />
            <div>
              <h2 className="text-2xl font-semibold">{user?.name}</h2>
              <p className="text-zinc-400">{user?.email}</p>
            </div>
          </div>
        </div>

        {/* Profile Picture Selection */}
        <div className="bg-zinc-900 p-8 rounded-2xl mb-8">
          <h3 className="text-xl font-semibold mb-6">Choose Profile Picture</h3>
          <div className="grid grid-cols-3 md:grid-cols-6 gap-4">
            {profilePictures.map((pic, index) => (
              <button
                key={index}
                onClick={() => setSelectedPicture(pic)}
                className={`p-2 rounded-xl border-2 transition-all ${
                  selectedPicture === pic
                    ? 'border-green-500 bg-green-500/20'
                    : 'border-zinc-700 hover:border-zinc-500'
                }`}
              >
                <img
                  src={pic}
                  alt={`Avatar ${index + 1}`}
                  className="w-full aspect-square rounded-lg"
                />
              </button>
            ))}
          </div>
          <button
            onClick={updateProfilePicture}
            disabled={loading}
            className="mt-6 w-full py-3 rounded-xl bg-green-500 text-black font-semibold hover:bg-green-400 transition disabled:opacity-50"
          >
            {loading ? 'Updating...' : 'Update Profile Picture'}
          </button>
        </div>

        {/* Logout Button */}
        <button
          onClick={logout}
          className="w-full py-3 rounded-xl bg-red-500 text-white font-semibold hover:bg-red-400 transition"
        >
          Logout
        </button>
      </div>
    </div>
  );
}
