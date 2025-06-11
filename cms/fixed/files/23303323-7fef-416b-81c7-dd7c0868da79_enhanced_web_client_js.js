// Enhanced JavaScript for Web Client - Replace the <script> section in your HTML

// Application State
let currentUser = null;
let authToken = localStorage.getItem('authToken');
let currentView = 'posts';
let posts = [];

// API Configuration
const API_BASE = 'http://localhost:8080';

// Utility Functions
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alert-container');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    
    alertContainer.appendChild(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) element.classList.remove('hidden');
}

function hideLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) element.classList.add('hidden');
}

// API Functions
async function apiCall(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    };

    if (authToken) {
        config.headers.Authorization = `Bearer ${authToken}`;
    }

    try {
        const response = await fetch(url, config);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || `HTTP ${response.status}`);
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Authentication Functions
async function login(event) {
    event.preventDefault();
    
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const data = await apiCall('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        authToken = data.token;
        localStorage.setItem('authToken', authToken);
        currentUser = { id: data.user_id, username: data.username };
        
        showAlert('Login successful!', 'success');
        showApp();
    } catch (error) {
        showAlert(error.message, 'error');
    }
}

async function register(event) {
    event.preventDefault();
    
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;

    try {
        const data = await apiCall('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password })
        });

        authToken = data.token;
        localStorage.setItem('authToken', authToken);
        currentUser = { id: data.user_id, username: data.username };
        
        showAlert('Registration successful!', 'success');
        showApp();
    } catch (error) {
        showAlert(error.message, 'error');
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    posts = [];
    localStorage.removeItem('authToken');
    showAuth();
    showAlert('Logged out successfully', 'info');
}

function showLogin() {
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('auth-title').textContent = 'Sign In';
    document.getElementById('auth-subtitle').textContent = 'Access your account';
}

function showRegister() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
    document.getElementById('auth-title').textContent = 'Create Account';
    document.getElementById('auth-subtitle').textContent = 'Join our community';
}

// View Management Functions
function showAuth() {
    document.getElementById('auth-view').classList.remove('hidden');
    document.getElementById('app-view').classList.add('hidden');
    document.getElementById('main-navbar').classList.add('hidden');
    
    // Clear any existing data
    posts = [];
    currentUser = null;
}

function showApp() {
    document.getElementById('auth-view').classList.add('hidden');
    document.getElementById('app-view').classList.remove('hidden');
    document.getElementById('main-navbar').classList.remove('hidden');
    
    // Update username display
    if (currentUser) {
        document.getElementById('username-display').textContent = currentUser.username;
    }
    
    loadCurrentUser();
    showView('posts');
}

function showView(viewName) {
    // Hide all views
    document.querySelectorAll('#app-view > div').forEach(view => {
        view.classList.add('hidden');
    });

    // Show selected view
    document.getElementById(`${viewName}-view`).classList.remove('hidden');

    // Update navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    const activeLink = document.querySelector(`[data-view="${viewName}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }

    currentView = viewName;

    // Load view data
    if (viewName === 'posts') {
        loadPosts();
    } else if (viewName === 'profile') {
        loadProfile();
    }
}

// Posts Functions
async function loadPosts() {
    showLoading('posts-loading');
    
    try {
        // Use the enhanced posts endpoint that includes like status
        const data = await apiCall('/api/posts');
        posts = data.posts;
        renderPosts();
    } catch (error) {
        showAlert('Failed to load posts: ' + error.message, 'error');
    } finally {
        hideLoading('posts-loading');
    }
}

function renderPosts() {
    const container = document.getElementById('posts-container');
    container.innerHTML = '';

    if (posts.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #666; grid-column: 1/-1;">No posts found. Create your first post!</p>';
        return;
    }

    posts.forEach(post => {
        const postElement = createPostElement(post);
        container.appendChild(postElement);
    });
}

function createPostElement(post) {
    const div = document.createElement('div');
    div.className = 'post-card';
    
    const isOwner = currentUser && post.author_id === currentUser.id;
    const createdAt = new Date(post.created_at * 1000).toLocaleDateString();
    const hasLiked = post.has_liked || false; // From API response
    
    div.innerHTML = `
        <div class="post-title">${escapeHtml(post.title)}</div>
        <div class="post-meta">
            By ${escapeHtml(post.author_username)} • ${createdAt} • ${post.views || 0} views • ${post.likes || 0} likes
        </div>
        <div class="post-content">${escapeHtml(post.content).substring(0, 200)}${post.content.length > 200 ? '...' : ''}</div>
        ${post.tags && post.tags.length > 0 ? `
            <div class="post-tags">
                ${post.tags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}
            </div>
        ` : ''}
        <div class="post-actions">
            ${hasLiked ? `
                <button class="btn btn-small btn-secondary btn-like liked" 
                        onclick="unlikePost('${post._key}')">
                    💚 Liked (${post.likes || 0})
                </button>
            ` : `
                <button class="btn btn-small btn-secondary btn-like" 
                        onclick="likePost('${post._key}')">
                    👍 Like (${post.likes || 0})
                </button>
            `}
            ${isOwner ? `
                <button class="btn btn-small btn-secondary" onclick="editPost('${post._key}')">
                    ✏️ Edit
                </button>
                <button class="btn btn-small btn-danger" onclick="deletePost('${post._key}')">
                    🗑️ Delete
                </button>
            ` : ''}
        </div>
    `;
    
    return div;
}

function showCreatePost() {
    document.getElementById('post-modal-title').textContent = 'Create Post';
    document.getElementById('post-form').reset();
    document.getElementById('post-id').value = '';
    document.getElementById('post-published').checked = true;
    document.getElementById('post-modal').classList.add('active');
}

function editPost(postId) {
    const post = posts.find(p => p._key === postId);
    if (!post) return;

    document.getElementById('post-modal-title').textContent = 'Edit Post';
    document.getElementById('post-id').value = postId;
    document.getElementById('post-title').value = post.title;
    document.getElementById('post-content').value = post.content;
    document.getElementById('post-tags').value = post.tags ? post.tags.join(', ') : '';
    document.getElementById('post-published').checked = post.is_published;
    document.getElementById('post-modal').classList.add('active');
}

async function savePost(event) {
    event.preventDefault();
    
    const postId = document.getElementById('post-id').value;
    const title = document.getElementById('post-title').value;
    const content = document.getElementById('post-content').value;
    const tagsString = document.getElementById('post-tags').value;
    const isPublished = document.getElementById('post-published').checked;
    
    const tags = tagsString ? tagsString.split(',').map(tag => tag.trim()).filter(tag => tag) : [];
    
    const postData = {
        title,
        content,
        tags,
        is_published: isPublished
    };

    try {
        if (postId) {
            // Edit existing post
            await apiCall(`/api/posts/${postId}`, {
                method: 'PUT',
                body: JSON.stringify(postData)
            });
            showAlert('Post updated successfully!', 'success');
        } else {
            // Create new post
            await apiCall('/api/posts', {
                method: 'POST',
                body: JSON.stringify(postData)
            });
            showAlert('Post created successfully!', 'success');
        }
        
        closeModal();
        loadPosts();
    } catch (error) {
        showAlert('Failed to save post: ' + error.message, 'error');
    }
}

async function deletePost(postId) {
    if (!confirm('Are you sure you want to delete this post?')) return;

    try {
        await apiCall(`/api/posts/${postId}`, {
            method: 'DELETE'
        });
        showAlert('Post deleted successfully!', 'success');
        loadPosts();
    } catch (error) {
        showAlert('Failed to delete post: ' + error.message, 'error');
    }
}

// Enhanced Like Functions
async function likePost(postId) {
    try {
        const result = await apiCall(`/api/posts/${postId}/like`, {
            method: 'POST'
        });
        
        showAlert('Post liked!', 'success');
        loadPosts(); // Refresh to show updated state
    } catch (error) {
        if (error.message.includes('already liked')) {
            showAlert('You have already liked this post!', 'info');
            loadPosts(); // Refresh to sync state
        } else {
            showAlert('Failed to like post: ' + error.message, 'error');
        }
    }
}

async function unlikePost(postId) {
    try {
        const result = await apiCall(`/api/posts/${postId}/like`, {
            method: 'DELETE'
        });
        
        showAlert('Post unliked!', 'info');
        loadPosts(); // Refresh to show updated state
    } catch (error) {
        if (error.message.includes('not liked')) {
            showAlert('You have not liked this post!', 'info');
            loadPosts(); // Refresh to sync state
        } else {
            showAlert('Failed to unlike post: ' + error.message, 'error');
        }
    }
}

// Profile Functions
async function loadCurrentUser() {
    try {
        const data = await apiCall('/api/auth/profile');
        currentUser = { ...currentUser, ...data };
    } catch (error) {
        console.error('Failed to load user profile:', error);
        // If token is invalid, logout
        if (error.message.includes('Invalid token') || error.message.includes('expired')) {
            logout();
        }
    }
}

async function loadProfile() {
    showLoading('profile-loading');
    
    try {
        const [profileData, collectionsData] = await Promise.all([
            apiCall('/api/auth/profile'),
            apiCall('/api/collections')
        ]);

        renderProfile(profileData, collectionsData);
    } catch (error) {
        showAlert('Failed to load profile: ' + error.message, 'error');
    } finally {
        hideLoading('profile-loading');
    }
}

function renderProfile(profile, collections) {
    const container = document.getElementById('profile-content');
    const userPosts = posts.filter(post => post.author_id === profile._key);
    const joinDate = new Date(profile.created_at * 1000).toLocaleDateString();
    const lastLogin = profile.last_login ? new Date(profile.last_login * 1000).toLocaleDateString() : 'Never';

    container.innerHTML = `
        <div class="profile-info">
            <div class="profile-stat">
                <div class="profile-stat-value">${userPosts.length}</div>
                <div class="profile-stat-label">Posts Created</div>
            </div>
            <div class="profile-stat">
                <div class="profile-stat-value">${userPosts.reduce((sum, post) => sum + (post.likes || 0), 0)}</div>
                <div class="profile-stat-label">Total Likes Received</div>
            </div>
            <div class="profile-stat">
                <div class="profile-stat-value">${userPosts.reduce((sum, post) => sum + (post.views || 0), 0)}</div>
                <div class="profile-stat-label">Total Views</div>
            </div>
            <div class="profile-stat">
                <div class="profile-stat-value">${userPosts.filter(post => post.has_liked).length}</div>
                <div class="profile-stat-label">Posts You Liked</div>
            </div>
        </div>
        
        <div class="form-group">
            <label class="form-label">Username</label>
            <input type="text" class="form-input" value="${escapeHtml(profile.username)}" readonly>
        </div>
        
        <div class="form-group">
            <label class="form-label">Email</label>
            <input type="email" class="form-input" value="${escapeHtml(profile.email)}" readonly>
        </div>
        
        <div class="form-group">
            <label class="form-label">Member Since</label>
            <input type="text" class="form-input" value="${joinDate}" readonly>
        </div>
        
        <div class="form-group">
            <label class="form-label">Last Login</label>
            <input type="text" class="form-input" value="${lastLogin}" readonly>
        </div>
        
        <div class="form-group">
            <label class="form-label">Account Status</label>
            <input type="text" class="form-input" value="${profile.is_active ? 'Active' : 'Inactive'}" readonly>
        </div>
        
        <div style="margin-top: 2rem;">
            <button class="btn btn-secondary" onclick="showUserStats()">
                📊 View Detailed Statistics
            </button>
        </div>
    `;
}

async function showUserStats() {
    try {
        const likedPosts = await apiCall('/api/users/liked-posts');
        showAlert(`You have liked ${likedPosts.count} posts total!`, 'info');
    } catch (error) {
        showAlert('Failed to load user statistics: ' + error.message, 'error');
    }
}

// Modal Functions
function closeModal() {
    document.getElementById('post-modal').classList.remove('active');
}

// Utility Functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Enhanced Authentication Check
async function checkAuthStatus() {
    if (!authToken) {
        showAuth();
        return false;
    }
    
    try {
        // Verify token is still valid
        await apiCall('/api/auth/profile');
        return true;
    } catch (error) {
        // Token is invalid or expired
        authToken = null;
        localStorage.removeItem('authToken');
        showAuth();
        showAlert('Session expired. Please log in again.', 'info');
        return false;
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', async function() {
    // Check authentication status
    const isAuthenticated = await checkAuthStatus();
    
    if (isAuthenticated) {
        showApp();
    } else {
        showAuth();
    }

    // Navigation event listeners
    document.querySelectorAll('[data-view]').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            showView(this.dataset.view);
        });
    });

    // Modal close on outside click
    document.getElementById('post-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeModal();
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
});

// Health check on load
apiCall('/api/health').then(() => {
    console.log('✅ API connection successful');
}).catch(() => {
    showAlert('❌ Cannot connect to API server. Please ensure the server is running on ' + API_BASE, 'error');
});